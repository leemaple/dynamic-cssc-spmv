from __future__ import annotations

import bz2
import csv
import ctypes
import errno
import gzip
import hashlib
import json
import os
import platform
import re
import secrets
import sqlite3
import stat
import sys
import sysconfig
import tempfile
from collections import Counter, deque
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from zoneinfo import TZPATH, ZoneInfo

from dynamic_cssc.evidence_compatibility import (
    EvidenceCompatibilityError,
    EvidenceRole,
    capture_behavior_inventory,
    repository_behavior_paths,
    verify_current_role_source,
)

ACQUISITION_RECEIPT_SCHEMA = "dynamic-cssc-acquisition-receipt-v6"
ACQUISITION_TRACE_BINDING_SCHEMA = "dynamic-cssc-trace-acquisition-binding-v2"
CANONICAL_RAW_EVENT_SCHEMA = "dynamic-cssc-canonical-raw-event-v1"
PUBLICATION_MAPPING_SCHEMA = "dynamic-cssc-publication-mapping-v1"
PUBLICATION_QUERY_VECTOR_SCHEMA = "dynamic-cssc-publication-query-vector-v1"
PUBLICATION_QUERY_VECTOR_SEED = 2026082302
PUBLICATION_SOURCE_PARTITION_COUNT = 5
PUBLICATION_TRACE_MANIFEST_SCHEMA = "dynamic-cssc-publication-trace-manifest-v7"
PUBLICATION_TRANSITION_SCHEMA = "dynamic-cssc-publication-transition-v3"
REPOSITORY_PROVENANCE_SCHEMA = "dynamic-cssc-repository-provenance-v1"
PARSER_RUNTIME_SCHEMA = "dynamic-cssc-publication-parser-runtime-v1"

_SHA256 = re.compile(r"[0-9a-f]{64}")
_GIT_OBJECT_ID = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
_NYC_TZIF_SHA256 = "e9ed07d7bee0c76a9d442d091ef1f01668fee7c4f26014c0a868b19fe6c18a95"
_PUBLICATION_PYTHON_VERSION = (3, 12, 13)
_PUBLICATION_BEHAVIOR_PATHS = repository_behavior_paths(EvidenceRole.TRACE)
_STACK_OVERFLOW_URLS = {
    "a2q": "https://snap.stanford.edu/data/sx-stackoverflow-a2q.txt.gz",
    "c2q": "https://snap.stanford.edu/data/sx-stackoverflow-c2q.txt.gz",
    "c2a": "https://snap.stanford.edu/data/sx-stackoverflow-c2a.txt.gz",
}
_SIMPLEWIKI_URL = (
    "https://dumps.wikimedia.org/other/mediawiki_history/2026-07/simplewiki/"
    "2026-07.simplewiki.all-time.tsv.bz2"
)
_MEDIAWIKI_HISTORY_FIELD_COUNT = 78
_MEDIAWIKI_HISTORY_INDEX = {
    "wiki_db": 0,
    "event_entity": 2,
    "event_type": 3,
    "event_timestamp": 4,
    "event_user_id": 6,
    "event_user_is_anonymous": 19,
    "event_user_is_temporary": 20,
    "event_user_is_permanent": 21,
    "page_id": 28,
    "page_namespace_historical": 31,
}
_NYC_ZONE_URL = "https://d37ci6vzurychx.cloudfront.net/misc/taxi_zone_lookup.csv"
_NYC_TRIP_URLS = {
    f"yellow-2022-{month:02d}": (
        f"https://d37ci6vzurychx.cloudfront.net/trip-data/yellow_tripdata_2022-{month:02d}.parquet"
    )
    for month in range(1, 13)
}
_SOURCE_MEDIA_TYPES = {
    **{
        source_url: frozenset({"application/gzip", "application/x-gzip"})
        for source_url in _STACK_OVERFLOW_URLS.values()
    },
    _SIMPLEWIKI_URL: frozenset({"application/octet-stream"}),
    _NYC_ZONE_URL: frozenset({"text/csv"}),
    **{
        source_url: frozenset({"application/x-www-form-urlencoded; charset=utf-8"})
        for source_url in _NYC_TRIP_URLS.values()
    },
}
_DATASET_RELEASES = {
    "stack-overflow": "snap-stackoverflow-temporal-network",
    "simplewiki-2026-07": "mediawiki-history-2026-07-simplewiki-all-time",
    "nyc-tlc-yellow-2022": "nyc-tlc-yellow-trip-records-2022",
}
_LICENSE_TERMS_URLS = {
    "stack-overflow": frozenset(
        {
            "https://stackoverflow.com/legal/terms-of-service/public",
            "https://stackoverflow.com/help/licensing",
        }
    ),
    "simplewiki-2026-07": frozenset(
        {"https://dumps.wikimedia.org/other/mediawiki_history/readme.html"}
    ),
    "nyc-tlc-yellow-2022": frozenset(
        {
            "https://opendata.cityofnewyork.us/faq/",
            "https://opendata.cityofnewyork.us/overview/",
            "https://cityofnewyork.github.io/opendatatsm/publicpolicies.html",
            "https://www.nyc.gov/main/terms-of-use",
        }
    ),
}
_LICENSE_TERMS_SECTION_ANCHORS = {
    **{
        source_url: None
        for source_urls in _LICENSE_TERMS_URLS.values()
        for source_url in source_urls
    },
    "https://opendata.cityofnewyork.us/overview/": "termsofuse",
}
_LICENSE_TERMS_MEDIA_TYPES = {
    source_url: frozenset({"text/html", "text/html; charset=utf-8"})
    for source_url in _LICENSE_TERMS_SECTION_ANCHORS
}
_NORMALIZATION_CONTRACTS = {
    "stack-overflow": {
        "adapter": "snap-stack-overflow-typed-union-v1",
        "timestamp_parser": "unix-seconds-utc",
        "directed": True,
        "self_loop_rule": "drop-and-count",
        "interaction_type_source": "typed-object-role",
    },
    "simplewiki-2026-07": {
        "adapter": "mediawiki-history-simplewiki-headerless-78-column-v1",
        "timestamp_parser": "mediawiki-history-utc",
        "directed": True,
        "row_identity": "historical-namespace-0-page-id",
        "column_identity": "permanent-event-user-id",
    },
    "nyc-tlc-yellow-2022": {
        "adapter": "nyc-tlc-yellow-time-expanded-od-v1",
        "python_runtime": "cpython-3.12.13",
        "parquet_engine": "pyarrow-25.0.1",
        "timestamp_parser": "america-new-york-fold-zero-to-utc",
        "ambiguous_local_time_rule": "first-occurrence-fold-zero",
        "nonexistent_local_time_rule": "reject-and-count",
        "monthly_partition_rule": "pickup-local-year-month-must-match-source-role",
        "dropoff_month_boundary_rule": "allowed-after-valid-pickup",
        "timezone_tzif_sha256": _NYC_TZIF_SHA256,
        "directed": True,
        "time_bin": "local-15-minute-bin-of-week",
        "valid_zone_source": "official-taxi-zone-lookup",
    },
}


@dataclass(frozen=True, slots=True)
class _TraceConfig:
    rows: int = 4096
    cols: int = 8193
    mapping_prefix_numerator: int = 1
    mapping_prefix_denominator: int = 10
    source_partitions: int = PUBLICATION_SOURCE_PARTITION_COUNT
    coefficient_cap: int = 7
    event_window_size: int = 32_768
    accepted_events_per_second: int = 128
    target_accepted_events: int = 131_072
    minimum_logical_changes: int = 65_536
    microbatch_cap: int = 64
    minimum_complete_window_lower_bound: int = 1_000
    maximum_row_nonzeros: int = 4096
    allow_fixture_tlc_csv: bool = False


_PRODUCTION_CONFIG = _TraceConfig()


@dataclass(frozen=True, slots=True)
class LicenseTermsObject:
    """One locally retained official terms page and its HTTP acquisition facts."""

    source_url: str
    final_url: str
    http_status: int
    media_type: str
    retrieval_utc: str
    http_etag: str | None
    http_last_modified: str | None
    section_anchor: str | None
    path: Path
    byte_count: int
    sha256: str


@dataclass(frozen=True, slots=True)
class LocalSourceObject:
    """Private parser projection of closed acquisition facts and one local object."""

    role: str
    path: Path
    source_url: str
    final_url: str
    http_status: int
    media_type: str
    retrieval_utc: str
    byte_count: int
    http_etag: str | None
    http_last_modified: str | None
    local_sha256: str
    publisher_sha256: str | None
    license_terms_objects: tuple[LicenseTermsObject, ...]
    attribution_text: str


_SourceSnapshotObserver = Callable[[LocalSourceObject, LocalSourceObject], None]


@dataclass(frozen=True, slots=True)
class _RepositorySnapshot:
    source_git_sha: str
    behavior_source_blob_sha256: Mapping[str, str]
    verification_mode: str


def _test_only_repository_snapshot() -> _RepositorySnapshot:
    """Return a conspicuously synthetic snapshot for private functional-test seams."""

    return _RepositorySnapshot(
        source_git_sha="f" * 40,
        behavior_source_blob_sha256=MappingProxyType(
            {
                path: f"{index:064x}"
                for index, path in enumerate(_PUBLICATION_BEHAVIOR_PATHS, start=1)
            }
        ),
        verification_mode="test-only-fixed-repository-snapshot-v1",
    )


def _read_regular_file_no_follow(path: Path) -> bytes:
    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("clean-HEAD verification requires OS O_NOFOLLOW support")
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as error:
        raise RuntimeError(f"behavior source is missing from the worktree: {path}") from error
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise RuntimeError(f"behavior source must be a non-symlink regular file: {path}")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | os.O_NONBLOCK,
        )
    except OSError as error:
        raise RuntimeError(f"behavior source cannot be opened securely: {path}") from error
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise RuntimeError(f"behavior source must remain a regular file: {path}")
        return handle.read()


def _verify_clean_repository_snapshot(
    repository_root: Path,
) -> _RepositorySnapshot:
    """Bind trace behavior to the one repository-owned hardened role verifier."""

    try:
        attestation = verify_current_role_source(EvidenceRole.TRACE, repository_root)
    except EvidenceCompatibilityError as error:
        raise RuntimeError(
            f"publication provenance failed hardened trace source verification: {error}"
        ) from error
    return _RepositorySnapshot(
        source_git_sha=attestation.git_sha,
        behavior_source_blob_sha256=attestation.behavior_source_blob_sha256,
        verification_mode="hardened-trace-role-git-object-worktree-v1",
    )


def _require_path_outside_repository(path: Path, repository_root: Path, *, field: str) -> None:
    """Keep raw inputs and generated evidence outside the clean source checkout."""

    if not isinstance(path, Path) or not isinstance(repository_root, Path):
        raise TypeError("publication paths and repository_root must be pathlib.Path values")
    if type(field) is not str or not field:
        raise TypeError("publication path field must be a nonempty string")
    normalized_root = repository_root.resolve()
    normalized_path = path.resolve(strict=False)
    if normalized_path == normalized_root or normalized_root in normalized_path.parents:
        raise ValueError(f"{field} must live outside the source checkout")


@dataclass(frozen=True, slots=True)
class CanonicalRawEvent:
    schema_version: str
    timestamp_utc: str
    source_file_ordinal: int
    within_file_ordinal: int
    canonical_source_id: str
    canonical_target_id: str
    source_event_type: str


@dataclass(frozen=True, slots=True)
class AcquisitionReceipt:
    schema_version: str
    dataset_id: str
    dataset_release: str
    role: str
    source_url: str
    final_url: str
    http_status: int
    media_type: str
    retrieval_utc: str
    byte_count: int
    http_etag: str | None
    http_last_modified: str | None
    local_sha256: str
    publisher_sha256: str | None
    license_terms_set_sha256: str
    license_terms_objects: tuple[Mapping[str, object], ...]
    attribution_text: str
    redistribution_policy: str
    rejected_event_counts: Mapping[str, int]


@dataclass(frozen=True, slots=True)
class CanonicalRawEventBatch:
    dataset_id: str
    dataset_release: str
    events: tuple[CanonicalRawEvent, ...]
    receipts: tuple[AcquisitionReceipt, ...]


@dataclass(frozen=True, slots=True)
class PublicationTraceRequest:
    dataset_id: str
    semantics: str
    source_partition: int
    acquisition_bundle_dir: Path


@dataclass(frozen=True, slots=True)
class _LocalTraceRequest:
    """Verified local objects passed only across the module's private seam."""

    dataset_id: str
    semantics: str
    source_partition: int
    sources: tuple[LocalSourceObject, ...]


@dataclass(frozen=True, slots=True)
class _VerifiedAcquisitionInput:
    request: _LocalTraceRequest
    binding: Mapping[str, object]


def _require_pytest_fixture_seam() -> None:
    marker = os.environ.get("PYTEST_CURRENT_TEST")
    if not marker or "tests/test_" not in marker:
        raise RuntimeError("the local-source fixture seam is available only under pytest")


def _local_sources_from_verified_source_set(
    root: Path,
    source_set: Mapping[str, object],
) -> tuple[LocalSourceObject, ...]:
    """Project an already closed acquisition source-set into private parser objects."""

    raw_terms = source_set.get("terms_objects")
    raw_objects = source_set.get("objects")
    if type(raw_terms) is not list or type(raw_objects) is not list:
        raise ValueError("verified acquisition source-set has malformed object arrays")
    terms: list[LicenseTermsObject] = []
    for index, raw_term in enumerate(raw_terms):
        if type(raw_term) is not dict:
            raise ValueError(f"verified terms object {index} is malformed")
        local_path = raw_term.get("local_path")
        if type(local_path) is not str:
            raise ValueError(f"verified terms object {index} local_path is malformed")
        terms.append(
            LicenseTermsObject(
                source_url=str(raw_term["source_url"]),
                final_url=str(raw_term["final_url"]),
                http_status=int(raw_term["http_status"]),
                media_type=str(raw_term["media_type"]),
                retrieval_utc=str(raw_term["retrieval_utc"]),
                http_etag=raw_term["http_etag"],  # type: ignore[arg-type]
                http_last_modified=raw_term["http_last_modified"],  # type: ignore[arg-type]
                section_anchor=raw_term["section_anchor"],  # type: ignore[arg-type]
                path=root / local_path,
                byte_count=int(raw_term["byte_count"]),
                sha256=str(raw_term["sha256"]),
            )
        )
    canonical_terms = tuple(terms)
    sources: list[LocalSourceObject] = []
    for index, raw_object in enumerate(raw_objects):
        if type(raw_object) is not dict:
            raise ValueError(f"verified source object {index} is malformed")
        local_path = raw_object.get("local_path")
        if type(local_path) is not str:
            raise ValueError(f"verified source object {index} local_path is malformed")
        sources.append(
            LocalSourceObject(
                role=str(raw_object["role"]),
                path=root / local_path,
                source_url=str(raw_object["source_url"]),
                final_url=str(raw_object["final_url"]),
                http_status=int(raw_object["http_status"]),
                media_type=str(raw_object["media_type"]),
                retrieval_utc=str(raw_object["retrieval_utc"]),
                byte_count=int(raw_object["byte_count"]),
                http_etag=raw_object["http_etag"],  # type: ignore[arg-type]
                http_last_modified=raw_object["http_last_modified"],  # type: ignore[arg-type]
                local_sha256=str(raw_object["local_sha256"]),
                publisher_sha256=raw_object["publisher_sha256"],  # type: ignore[arg-type]
                license_terms_objects=canonical_terms,
                attribution_text=str(raw_object["attribution_text"]),
            )
        )
    return tuple(sources)


def _current_acquisition_repository_snapshot(repository_root: Path) -> object:
    """Build the acquisition verifier's snapshot only from central clean-HEAD state."""

    from dynamic_cssc.publication_acquisition import _RepositorySnapshot as Snapshot

    try:
        attestation = verify_current_role_source(EvidenceRole.ACQUISITION, repository_root)
        inventory = capture_behavior_inventory(
            EvidenceRole.ACQUISITION,
            source_git_sha=attestation.git_sha,
            repository_root=repository_root,
        )
    except EvidenceCompatibilityError as error:
        raise RuntimeError(
            f"publication acquisition provenance failed hardened verification: {error}"
        ) from error
    return Snapshot(
        source_git_sha=attestation.git_sha,
        behavior_inventory=MappingProxyType(inventory),
        verification_mode="hardened-acquisition-role-git-object-worktree-v1",
    )


def _verified_acquisition_input(
    request: PublicationTraceRequest,
    *,
    repository_root: Path,
    acquisition_repository_snapshot: object,
) -> _VerifiedAcquisitionInput:
    """Close and project one acquisition transaction before any parser sees paths."""

    from dynamic_cssc.publication_acquisition import (
        ACQUISITION_TRANSACTION_SCHEMA,
        LOCAL_SOURCE_SET_SCHEMA,
        _read_canonical_json_object,
        _verify_acquisition_bundle,
    )

    if type(request) is not PublicationTraceRequest:
        raise TypeError("request must be an exact PublicationTraceRequest")
    if not isinstance(request.acquisition_bundle_dir, Path):
        raise TypeError("acquisition_bundle_dir must be a pathlib.Path")
    _require_path_outside_repository(
        request.acquisition_bundle_dir,
        repository_root,
        field="acquisition bundle directory",
    )
    verified = _verify_acquisition_bundle(
        request.acquisition_bundle_dir,
        repository_snapshot=acquisition_repository_snapshot,  # type: ignore[arg-type]
        repository_root=repository_root,
    )
    if verified.dataset_id != request.dataset_id:
        raise ValueError("requested dataset_id does not match the acquisition transaction")
    source_set, source_set_bytes = _read_canonical_json_object(
        verified.source_set_path,
        "trace acquisition source-set",
    )
    transaction, transaction_bytes = _read_canonical_json_object(
        verified.transaction_path,
        "trace acquisition transaction",
    )
    if hashlib.sha256(source_set_bytes).hexdigest() != verified.source_set_sha256:
        raise ValueError("source-set changed after closed acquisition verification")
    if hashlib.sha256(transaction_bytes).hexdigest() != verified.transaction_sha256:
        raise ValueError("acquisition transaction changed after closed verification")
    repository_provenance = transaction.get("repository_provenance")
    if type(repository_provenance) is not dict:
        raise ValueError("verified acquisition repository provenance is malformed")
    verification_mode = repository_provenance.get("verification_mode")
    test_only = verification_mode == "test-only-fixed-repository-snapshot-v1"
    if verification_mode not in {
        "hardened-acquisition-role-git-object-worktree-v1",
        "test-only-fixed-repository-snapshot-v1",
    }:
        raise ValueError("verified acquisition repository provenance mode is not recognized")
    binding: dict[str, object] = {
        "schema_version": ACQUISITION_TRACE_BINDING_SCHEMA,
        "dataset_id": request.dataset_id,
        "dataset_release": frozen_dataset_release(request.dataset_id),
        "acquisition_transaction_schema_version": ACQUISITION_TRANSACTION_SCHEMA,
        "acquisition_transaction_sha256": verified.transaction_sha256,
        "source_set_schema_version": LOCAL_SOURCE_SET_SCHEMA,
        "source_set_sha256": verified.source_set_sha256,
        "repository_provenance": repository_provenance,
        "verification": {
            "bundle_member_set_exact": True,
            "bundle_members_rehashed_no_follow": True,
            "embedded_central_inventory_verified": not test_only,
            "network_fetch_recorded": transaction.get("network_fetch_performed") is True,
            "source_and_terms_objects_rehashed_no_follow": True,
            "transaction_chain_verified": True,
        },
        "authority": {
            "state": (
                "HOLD-test-only-fixture-no-post-run-anchor"
                if test_only
                else "HOLD-no-repository-post-run-anchor"
            ),
            "formal_authority_granted": False,
            "acquisition_network_authority_verified": False,
            "post_run_anchor_verified": False,
            "evidence_compatibility_verified": False,
            "claims_authorized": False,
        },
    }
    return _VerifiedAcquisitionInput(
        request=_LocalTraceRequest(
            dataset_id=request.dataset_id,
            semantics=request.semantics,
            source_partition=request.source_partition,
            sources=_local_sources_from_verified_source_set(verified.output_dir, source_set),
        ),
        binding=MappingProxyType(binding),
    )


def _test_only_fixture_acquisition_binding(
    request: _LocalTraceRequest,
) -> Mapping[str, object]:
    """Describe the narrow source-object fixture seam without granting authority."""

    _require_pytest_fixture_seam()
    from dynamic_cssc.publication_acquisition import (
        ACQUISITION_TRANSACTION_SCHEMA,
        LOCAL_SOURCE_SET_SCHEMA,
    )
    from dynamic_cssc.publication_acquisition import (
        _test_only_repository_snapshot as acquisition_snapshot,
    )

    snapshot = acquisition_snapshot()
    fixture_identity = _canonical_json_bytes(
        {
            "dataset_id": request.dataset_id,
            "objects": [
                {
                    "local_sha256": source.local_sha256,
                    "role": source.role,
                }
                for source in request.sources
            ],
            "schema_version": "dynamic-cssc-test-local-source-fixture-v1",
        }
    )
    fixture_sha256 = hashlib.sha256(fixture_identity).hexdigest()
    return MappingProxyType(
        {
            "schema_version": ACQUISITION_TRACE_BINDING_SCHEMA,
            "dataset_id": request.dataset_id,
            "dataset_release": frozen_dataset_release(request.dataset_id),
            "acquisition_transaction_schema_version": ACQUISITION_TRANSACTION_SCHEMA,
            "acquisition_transaction_sha256": fixture_sha256,
            "source_set_schema_version": LOCAL_SOURCE_SET_SCHEMA,
            "source_set_sha256": hashlib.sha256(b"source-set\0" + fixture_identity).hexdigest(),
            "repository_provenance": {
                "source_git_sha": snapshot.source_git_sha,
                "verification_mode": snapshot.verification_mode,
                "behavior_inventory": dict(snapshot.behavior_inventory),
            },
            "verification": {
                "bundle_member_set_exact": False,
                "bundle_members_rehashed_no_follow": False,
                "embedded_central_inventory_verified": False,
                "network_fetch_recorded": False,
                "source_and_terms_objects_rehashed_no_follow": True,
                "transaction_chain_verified": False,
            },
            "authority": {
                "state": "HOLD-test-only-local-source-fixture",
                "formal_authority_granted": False,
                "acquisition_network_authority_verified": False,
                "post_run_anchor_verified": False,
                "evidence_compatibility_verified": False,
                "claims_authorized": False,
            },
        }
    )


@dataclass(frozen=True, slots=True)
class TransitionEventProvenance:
    """Canonical identity of the raw event that triggers or owns a transition."""

    canonical_raw_event_ordinal: int
    source_timestamp_utc: str
    source_file_ordinal: int
    within_file_ordinal: int
    source_event_type: str


@dataclass(frozen=True, slots=True)
class PublicationTransition:
    schema_version: str
    dataset_id: str
    dataset_release: str
    semantics: str
    source_partition: int
    repository_provenance_sha256: str
    accepted_event_ordinal: int
    transition_ordinal: int
    transition_cause: str
    trigger_event: TransitionEventProvenance
    subject_event: TransitionEventProvenance
    logical_time_numerator: int
    logical_time_denominator: int
    row_index: int
    column_index: int
    operation: str
    before: int
    after: int


@dataclass(frozen=True, slots=True)
class PublicationTraceBundle:
    manifest: dict[str, object]
    records: tuple[PublicationTransition, ...]
    manifest_bytes: bytes
    trace_jsonl_bytes: bytes
    query_vector_bytes: bytes
    checksums: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class _TransformResult:
    records: tuple[PublicationTransition, ...]
    filter_counts: dict[str, int]
    peak_row_nonzeros: int
    accepted_raw_event_sha256: str
    source_event_type_counts: dict[str, int]
    accepted_event_count: int
    transition_record_count: int
    operation_counts: dict[str, int]
    maximum_transition_group_size_observed: int
    event_window_peak_groups: int
    peak_live_coordinate_count: int


class _CanonicalEventStore:
    """Disk-backed total ordering for publication-scale source streams."""

    _INSERT_BATCH_SIZE = 16_384

    def __init__(self, path: Path) -> None:
        connection = sqlite3.connect(path)
        try:
            connection.execute("PRAGMA journal_mode=OFF")
            connection.execute("PRAGMA synchronous=OFF")
            connection.execute("PRAGMA temp_store=FILE")
            if connection.execute("PRAGMA temp_store").fetchone() != (1,):
                raise RuntimeError("canonical event store requires temp_store=FILE")
            connection.execute(
                """
                CREATE TABLE canonical_events (
                    timestamp_utc TEXT NOT NULL,
                    source_file_ordinal INTEGER NOT NULL,
                    within_file_ordinal INTEGER NOT NULL,
                    canonical_source_id TEXT NOT NULL,
                    canonical_target_id TEXT NOT NULL,
                    source_event_type TEXT NOT NULL,
                    UNIQUE (source_file_ordinal, within_file_ordinal)
                )
                """
            )
        except BaseException:
            with suppress(sqlite3.Error):
                connection.close()
            raise
        self._connection = connection
        self._pending: list[tuple[object, ...]] = []
        self._finalized = False

    def add(self, event: CanonicalRawEvent) -> None:
        if self._finalized:
            raise RuntimeError("canonical event store is already finalized")
        self._pending.append(
            (
                event.timestamp_utc,
                event.source_file_ordinal,
                event.within_file_ordinal,
                event.canonical_source_id,
                event.canonical_target_id,
                event.source_event_type,
            )
        )
        if len(self._pending) >= self._INSERT_BATCH_SIZE:
            self._flush()

    def _flush(self) -> None:
        if not self._pending:
            return
        self._connection.executemany(
            """
            INSERT INTO canonical_events VALUES (?, ?, ?, ?, ?, ?)
            """,
            self._pending,
        )
        self._pending.clear()

    def finalize(self) -> None:
        if self._finalized:
            return
        self._flush()
        self._connection.execute(
            """
            CREATE INDEX canonical_event_order
            ON canonical_events (timestamp_utc, source_file_ordinal, within_file_ordinal)
            """
        )
        self._connection.commit()
        self._finalized = True

    @property
    def count(self) -> int:
        if not self._finalized:
            raise RuntimeError("canonical event store must be finalized before reading")
        [row] = self._connection.execute("SELECT COUNT(*) FROM canonical_events")
        return int(row[0])

    def ordered_events(
        self, *, offset: int = 0, limit: int | None = None
    ) -> Iterator[CanonicalRawEvent]:
        if not self._finalized:
            raise RuntimeError("canonical event store must be finalized before reading")
        if type(offset) is not int or offset < 0:
            raise ValueError("event-store offset must be a nonnegative integer")
        if limit is not None and (type(limit) is not int or limit < 0):
            raise ValueError("event-store limit must be null or a nonnegative integer")
        query = (
            "SELECT timestamp_utc, source_file_ordinal, within_file_ordinal, "
            "canonical_source_id, canonical_target_id, source_event_type "
            "FROM canonical_events "
            "ORDER BY timestamp_utc, source_file_ordinal, within_file_ordinal "
            "LIMIT ? OFFSET ?"
        )
        sql_limit = -1 if limit is None else limit
        for row in self._connection.execute(query, (sql_limit, offset)):
            yield CanonicalRawEvent(
                schema_version=CANONICAL_RAW_EVENT_SCHEMA,
                timestamp_utc=str(row[0]),
                source_file_ordinal=int(row[1]),
                within_file_ordinal=int(row[2]),
                canonical_source_id=str(row[3]),
                canonical_target_id=str(row[4]),
                source_event_type=str(row[5]),
            )

    def mapping_for_partition(
        self,
        batch: CanonicalRawEventBatch,
        *,
        total_event_count: int,
        source_partition_id: int,
        config: _TraceConfig,
    ) -> tuple[dict[str, object], dict[str, int], dict[str, int], int, list[str]]:
        """Aggregate the frozen prefix mapping in SQLite with bounded Python state."""

        if not self._finalized:
            raise RuntimeError("canonical event store must be finalized before mapping")
        if sqlite3.sqlite_version_info < (3, 35, 0):
            raise RuntimeError("canonical mapping aggregation requires SQLite 3.35 or newer")
        try:
            store_count = self.count
        except sqlite3.Error as error:
            raise RuntimeError("canonical mapping aggregation failed") from error
        if type(total_event_count) is not int or total_event_count != store_count:
            raise ValueError("mapping total_event_count must equal the canonical store count")
        if type(source_partition_id) is not int or not (
            0 <= source_partition_id < config.source_partitions
        ):
            raise ValueError("mapping source_partition must be in the frozen partition range")
        prefix_count = (
            total_event_count * config.mapping_prefix_numerator // config.mapping_prefix_denominator
        )
        selected_rows_table_exists = False
        try:
            self._connection.create_function(
                "dynamic_cssc_source_partition",
                1,
                lambda identity: source_partition(batch.dataset_release, str(identity)),
                deterministic=True,
            )
            row_query = """
                WITH prefix AS MATERIALIZED (
                    SELECT canonical_source_id, canonical_target_id
                    FROM canonical_events
                    ORDER BY timestamp_utc COLLATE BINARY,
                             source_file_ordinal,
                             within_file_ordinal
                    LIMIT ?
                )
                SELECT canonical_source_id, COUNT(*) AS event_count
                FROM prefix
                WHERE dynamic_cssc_source_partition(canonical_source_id) = ?
                GROUP BY canonical_source_id COLLATE BINARY
                ORDER BY event_count DESC, canonical_source_id COLLATE BINARY ASC
                LIMIT ?
            """
            observed_row_ids = [
                str(row[0])
                for row in self._connection.execute(
                    row_query,
                    (prefix_count, source_partition_id, config.rows),
                )
            ]
            self._connection.execute("DROP TABLE IF EXISTS temp.selected_mapping_rows")
            self._connection.execute(
                "CREATE TEMP TABLE selected_mapping_rows "
                "(canonical_source_id TEXT COLLATE BINARY PRIMARY KEY) WITHOUT ROWID"
            )
            selected_rows_table_exists = True
            self._connection.executemany(
                "INSERT INTO selected_mapping_rows VALUES (?)",
                ((identity,) for identity in observed_row_ids),
            )
            column_query = """
                WITH prefix AS MATERIALIZED (
                    SELECT canonical_source_id, canonical_target_id
                    FROM canonical_events
                    ORDER BY timestamp_utc COLLATE BINARY,
                             source_file_ordinal,
                             within_file_ordinal
                    LIMIT ?
                )
                SELECT prefix.canonical_target_id, COUNT(*) AS event_count
                FROM prefix
                JOIN selected_mapping_rows
                  ON selected_mapping_rows.canonical_source_id = prefix.canonical_source_id
                GROUP BY prefix.canonical_target_id COLLATE BINARY
                ORDER BY event_count DESC,
                         prefix.canonical_target_id COLLATE BINARY ASC
                LIMIT ?
            """
            observed_column_ids = [
                str(row[0])
                for row in self._connection.execute(
                    column_query,
                    (prefix_count, config.cols),
                )
            ]
            self._connection.execute("DROP TABLE temp.selected_mapping_rows")
            selected_rows_table_exists = False
        except sqlite3.Error as error:
            if selected_rows_table_exists:
                with suppress(sqlite3.Error):
                    self._connection.execute("DROP TABLE IF EXISTS temp.selected_mapping_rows")
            raise RuntimeError("canonical mapping aggregation failed") from error
        return _mapping_from_observed_ids(
            batch,
            observed_row_ids=observed_row_ids,
            observed_column_ids=observed_column_ids,
            prefix_count=prefix_count,
            source_partition_id=source_partition_id,
            config=config,
        )

    def close(self) -> None:
        self._connection.close()


def _require_utc_timestamp(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{field} must be an RFC 3339 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ValueError(f"{field} must be a valid RFC 3339 UTC timestamp") from error
    if parsed.tzinfo != UTC:
        raise ValueError(f"{field} must be UTC")
    return value


def _validate_source_attestation(
    source: LocalSourceObject,
    *,
    expected_url: str,
    expected_license_urls: frozenset[str],
) -> None:
    if type(source) is not LocalSourceObject:
        raise TypeError("sources must contain exact LocalSourceObject values")
    if not isinstance(source.path, Path):
        raise ValueError("source path must be a pathlib.Path")
    try:
        source_mode = source.path.lstat().st_mode
    except FileNotFoundError as error:
        raise ValueError("source path must name an existing regular file") from error
    if stat.S_ISLNK(source_mode):
        raise ValueError("source path must not be a symbolic link")
    if not stat.S_ISREG(source_mode):
        raise ValueError("source path must name an existing regular file")
    if source.source_url != expected_url:
        raise ValueError(f"source_url does not match the frozen URL for role {source.role}")
    if source.final_url != source.source_url:
        raise ValueError("unexpected HTTP redirect: final_url must equal the frozen source_url")
    if type(source.http_status) is not int or source.http_status != 200:
        raise ValueError("http_status must be the strict integer 200")
    if source.media_type not in _SOURCE_MEDIA_TYPES[expected_url]:
        raise ValueError("media_type does not match the frozen type set for the source URL")
    _require_utc_timestamp(source.retrieval_utc, "retrieval_utc")
    if type(source.byte_count) is not int or source.byte_count < 0:
        raise ValueError("byte_count must be a nonnegative integer")
    if not isinstance(source.local_sha256, str) or not _SHA256.fullmatch(source.local_sha256):
        raise ValueError("local_sha256 must be a lowercase SHA-256 digest")
    if source.publisher_sha256 is not None and (
        not isinstance(source.publisher_sha256, str)
        or not _SHA256.fullmatch(source.publisher_sha256)
    ):
        raise ValueError("publisher_sha256 must be null or a lowercase SHA-256 digest")
    if source.publisher_sha256 is not None and source.publisher_sha256 != source.local_sha256:
        raise ValueError("publisher_sha256 does not match the verified local source object")
    for field, value in (
        ("http_etag", source.http_etag),
        ("http_last_modified", source.http_last_modified),
    ):
        if value is not None and (not isinstance(value, str) or not value):
            raise ValueError(f"{field} must be null or a nonempty string")
    _verified_license_terms_payload(
        source.license_terms_objects,
        expected_urls=expected_license_urls,
    )
    if not isinstance(source.attribution_text, str) or not source.attribution_text.strip():
        raise ValueError("attribution_text must be nonempty")


def _verified_license_terms_payload(
    terms_objects: tuple[LicenseTermsObject, ...],
    *,
    expected_urls: frozenset[str],
) -> tuple[tuple[dict[str, object], ...], str]:
    if type(terms_objects) is not tuple or any(
        type(item) is not LicenseTermsObject for item in terms_objects
    ):
        raise ValueError("license_terms_objects must be an exact tuple of terms objects")
    if tuple(item.source_url for item in terms_objects) != tuple(sorted(expected_urls)):
        raise ValueError("license terms objects must equal the exact frozen official URL set")
    payload: list[dict[str, object]] = []
    for item in terms_objects:
        if item.final_url != item.source_url:
            raise ValueError("unexpected HTTP redirect for a license terms object")
        if type(item.http_status) is not int or item.http_status != 200:
            raise ValueError("license terms http_status must be the strict integer 200")
        if type(item.media_type) is not str:
            raise ValueError("license terms media_type must match the frozen type set")
        normalized_media_type = "; ".join(
            part.strip().lower() for part in item.media_type.split(";")
        )
        if normalized_media_type not in _LICENSE_TERMS_MEDIA_TYPES[item.source_url]:
            raise ValueError("license terms media_type does not match the frozen type set")
        _require_utc_timestamp(item.retrieval_utc, "license terms retrieval_utc")
        for field, value in (
            ("license terms http_etag", item.http_etag),
            ("license terms http_last_modified", item.http_last_modified),
        ):
            if value is not None and (type(value) is not str or not value):
                raise ValueError(f"{field} must be null or a nonempty string")
        if item.section_anchor != _LICENSE_TERMS_SECTION_ANCHORS[item.source_url]:
            raise ValueError("license terms section anchor does not match the frozen value")
        if not isinstance(item.path, Path):
            raise ValueError("license terms path must be a pathlib.Path")
        if type(item.byte_count) is not int or item.byte_count < 0:
            raise ValueError("license terms byte_count must be a nonnegative integer")
        if type(item.sha256) is not str or _SHA256.fullmatch(item.sha256) is None:
            raise ValueError("license terms sha256 must be a lowercase SHA-256 digest")
        try:
            content = _read_regular_file_no_follow(item.path)
        except RuntimeError as error:
            raise ValueError("license terms path must name a secure regular file") from error
        if len(content) != item.byte_count:
            raise ValueError("license terms byte_count does not match the local terms object")
        if hashlib.sha256(content).hexdigest() != item.sha256:
            raise ValueError("license terms sha256 does not match the local terms object")
        payload.append(
            {
                "source_url": item.source_url,
                "final_url": item.final_url,
                "http_status": item.http_status,
                "media_type": normalized_media_type,
                "retrieval_utc": item.retrieval_utc,
                "http_etag": item.http_etag,
                "http_last_modified": item.http_last_modified,
                "section_anchor": item.section_anchor,
                "byte_count": item.byte_count,
                "sha256": item.sha256,
            }
        )
    canonical_payload = tuple(payload)
    return canonical_payload, hashlib.sha256(_canonical_json_bytes(canonical_payload)).hexdigest()


class _SourceSnapshotOwnershipChanged(RuntimeError):
    """A source-snapshot pathname no longer names its invocation-owned inode."""


def _source_snapshot_rename_no_replace(
    source_parent_fd: int,
    source_name: str,
    destination_parent_fd: int,
    destination_name: str,
) -> None:
    """Atomically rename one snapshot entry relative to stable parent descriptors."""

    libc = ctypes.CDLL(None, use_errno=True)
    encoded_source = os.fsencode(source_name)
    encoded_destination = os.fsencode(destination_name)
    ctypes.set_errno(0)
    if sys.platform == "darwin":
        try:
            rename_no_replace = libc.renameatx_np
        except AttributeError as error:
            raise RuntimeError(
                "source snapshot cleanup requires atomic descriptor-relative rename"
            ) from error
        rename_no_replace.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        rename_no_replace.restype = ctypes.c_int
        result = rename_no_replace(
            source_parent_fd,
            encoded_source,
            destination_parent_fd,
            encoded_destination,
            0x00000004,
        )
    elif sys.platform.startswith("linux"):
        try:
            rename_no_replace = libc.renameat2
        except AttributeError as error:
            raise RuntimeError(
                "source snapshot cleanup requires atomic descriptor-relative rename"
            ) from error
        rename_no_replace.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        rename_no_replace.restype = ctypes.c_int
        result = rename_no_replace(
            source_parent_fd,
            encoded_source,
            destination_parent_fd,
            encoded_destination,
            0x00000001,
        )
    else:
        raise RuntimeError("source snapshot cleanup requires atomic descriptor-relative rename")
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _source_snapshot_restore(
    parent_fd: int,
    quarantine_name: str,
    original_name: str,
) -> None:
    try:
        _source_snapshot_rename_no_replace(
            parent_fd,
            quarantine_name,
            parent_fd,
            original_name,
        )
    except OSError:
        # Never overwrite a newer object. Both entries remain if restoration loses a race.
        return


def _source_snapshot_entry_exists(parent_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _source_snapshot_claim_at(
    parent_fd: int,
    name: str,
    identity: tuple[int, int],
    *,
    directory: bool,
) -> tuple[str, int]:
    quarantine_name = f".{name}.owned-quarantine-{secrets.token_hex(16)}"
    _source_snapshot_rename_no_replace(
        parent_fd,
        name,
        parent_fd,
        quarantine_name,
    )
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    flags |= os.O_DIRECTORY if directory else os.O_NONBLOCK
    try:
        entry_fd = os.open(quarantine_name, flags, dir_fd=parent_fd)
        observed = os.fstat(entry_fd)
    except BaseException:
        _source_snapshot_restore(parent_fd, quarantine_name, name)
        raise
    expected_kind = stat.S_ISDIR(observed.st_mode) if directory else stat.S_ISREG(observed.st_mode)
    if not expected_kind or (observed.st_dev, observed.st_ino) != identity:
        os.close(entry_fd)
        _source_snapshot_restore(parent_fd, quarantine_name, name)
        raise _SourceSnapshotOwnershipChanged(name)
    return quarantine_name, entry_fd


def _remove_source_snapshot_if_owned(
    directory: Path,
    directory_identity: tuple[int, int],
    snapshot_path: Path,
    snapshot_identity: tuple[int, int] | None,
) -> None:
    """Quarantine and remove only the exact snapshot objects created here."""

    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("source snapshot cleanup requires no-follow directory descriptors")
    parent_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        parent_fd = os.open(directory.parent, parent_flags)
        directory_quarantine, directory_fd = _source_snapshot_claim_at(
            parent_fd,
            directory.name,
            directory_identity,
            directory=True,
        )
    except (OSError, _SourceSnapshotOwnershipChanged) as error:
        if "parent_fd" in locals():
            os.close(parent_fd)
        raise RuntimeError("source snapshot cleanup refused: directory identity changed") from error

    def restore_directory() -> None:
        _source_snapshot_restore(
            parent_fd,
            directory_quarantine,
            directory.name,
        )

    try:
        if snapshot_identity is not None:
            try:
                snapshot_quarantine, snapshot_fd = _source_snapshot_claim_at(
                    directory_fd,
                    snapshot_path.name,
                    snapshot_identity,
                    directory=False,
                )
            except (OSError, _SourceSnapshotOwnershipChanged) as error:
                restore_directory()
                raise RuntimeError(
                    "source snapshot cleanup refused: file identity changed"
                ) from error
            try:
                os.unlink(snapshot_quarantine, dir_fd=directory_fd)
            except OSError as error:
                restore_directory()
                raise RuntimeError("source snapshot cleanup failed") from error
            finally:
                os.close(snapshot_fd)
            if _source_snapshot_entry_exists(directory_fd, snapshot_path.name):
                restore_directory()
                raise RuntimeError("source snapshot cleanup refused: file replacement preserved")
        if os.listdir(directory_fd):
            restore_directory()
            raise RuntimeError("source snapshot cleanup refused: directory is not empty")
        try:
            os.rmdir(directory_quarantine, dir_fd=parent_fd)
        except OSError as error:
            restore_directory()
            raise RuntimeError("source snapshot cleanup failed") from error
        if _source_snapshot_entry_exists(parent_fd, directory.name):
            raise RuntimeError("source snapshot cleanup refused: directory replacement preserved")
    finally:
        os.close(directory_fd)
        os.close(parent_fd)


@contextmanager
def _verified_source_snapshot(
    source: LocalSourceObject,
    *,
    expected_url: str,
    expected_license_urls: frozenset[str],
    _test_only_after_snapshot: _SourceSnapshotObserver | None = None,
) -> Iterator[LocalSourceObject]:
    """Yield one verified private snapshot and delete it before returning."""

    _validate_source_attestation(
        source,
        expected_url=expected_url,
        expected_license_urls=expected_license_urls,
    )
    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("secure source snapshots require OS O_NOFOLLOW support")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | os.O_NONBLOCK
    try:
        source_fd = os.open(source.path, flags)
    except OSError as error:
        if error.errno == errno.ELOOP or source.path.is_symlink():
            raise ValueError("source path must not be a symbolic link") from error
        raise
    with os.fdopen(source_fd, "rb") as source_handle:
        if not stat.S_ISREG(os.fstat(source_fd).st_mode):
            raise ValueError("source path must name an existing regular file")
        temporary_root = Path(tempfile.mkdtemp(prefix="dynamic-cssc-source-snapshot-"))
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        temporary_fd = os.open(temporary_root, directory_flags)
        temporary_stat = os.fstat(temporary_fd)
        temporary_identity = (temporary_stat.st_dev, temporary_stat.st_ino)
        snapshot_path = temporary_root / "source-object"
        snapshot_identity: tuple[int, int] | None = None
        try:
            digest = hashlib.sha256()
            observed_bytes = 0
            snapshot_flags = (
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
            )
            snapshot_fd = os.open(
                snapshot_path.name,
                snapshot_flags,
                0o600,
                dir_fd=temporary_fd,
            )
            with os.fdopen(snapshot_fd, "wb") as snapshot_handle:
                snapshot_stat = os.fstat(snapshot_handle.fileno())
                snapshot_identity = (snapshot_stat.st_dev, snapshot_stat.st_ino)
                for chunk in iter(lambda: source_handle.read(1024 * 1024), b""):
                    observed_bytes += len(chunk)
                    digest.update(chunk)
                    snapshot_handle.write(chunk)
                snapshot_handle.flush()
                os.fsync(snapshot_handle.fileno())
                os.fchmod(snapshot_handle.fileno(), 0o400)
            if observed_bytes != source.byte_count:
                raise ValueError("byte_count does not match the local source object")
            if digest.hexdigest() != source.local_sha256:
                raise ValueError("local_sha256 does not match the local source object")
            snapshot_source = replace(source, path=snapshot_path)
            if _test_only_after_snapshot is not None:
                _test_only_after_snapshot(source, snapshot_source)
            yield snapshot_source
        finally:
            try:
                _remove_source_snapshot_if_owned(
                    temporary_root,
                    temporary_identity,
                    snapshot_path,
                    snapshot_identity,
                )
            finally:
                os.close(temporary_fd)


def _canonical_instant(timestamp: datetime) -> str:
    return timestamp.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _acquisition_receipt(
    *,
    dataset_id: str,
    source: LocalSourceObject,
    rejected: Mapping[str, int],
) -> AcquisitionReceipt:
    """Project one verified local source into the closed receipt schema."""

    terms_payload, terms_set_sha256 = _verified_license_terms_payload(
        source.license_terms_objects,
        expected_urls=_LICENSE_TERMS_URLS[dataset_id],
    )
    return AcquisitionReceipt(
        schema_version=ACQUISITION_RECEIPT_SCHEMA,
        dataset_id=dataset_id,
        dataset_release=_DATASET_RELEASES[dataset_id],
        role=source.role,
        source_url=source.source_url,
        final_url=source.final_url,
        http_status=source.http_status,
        media_type=source.media_type,
        retrieval_utc=source.retrieval_utc,
        byte_count=source.byte_count,
        http_etag=source.http_etag,
        http_last_modified=source.http_last_modified,
        local_sha256=source.local_sha256,
        publisher_sha256=source.publisher_sha256,
        license_terms_set_sha256=terms_set_sha256,
        license_terms_objects=terms_payload,
        attribution_text=source.attribution_text,
        redistribution_policy="derived-trace-and-download-by-source-only",
        rejected_event_counts=MappingProxyType(dict(sorted(rejected.items()))),
    )


def _stack_overflow_events(
    sources: Sequence[LocalSourceObject],
    *,
    event_sink: Callable[[CanonicalRawEvent], None] | None = None,
    _test_only_after_source_snapshot: _SourceSnapshotObserver | None = None,
) -> tuple[tuple[CanonicalRawEvent, ...], tuple[AcquisitionReceipt, ...]]:
    events: list[CanonicalRawEvent] = []
    emit = events.append if event_sink is None else event_sink
    receipts: list[AcquisitionReceipt] = []
    role_ordinals = {role: index for index, role in enumerate(("a2q", "c2q", "c2a"))}
    seen_roles: set[str] = set()
    for source in sources:
        if source.role not in _STACK_OVERFLOW_URLS:
            raise ValueError(f"unknown Stack Overflow source role: {source.role!r}")
        if source.role in seen_roles:
            raise ValueError(f"duplicate Stack Overflow source role: {source.role}")
        seen_roles.add(source.role)
        rejected: Counter[str] = Counter()
        with (
            _verified_source_snapshot(
                source,
                expected_url=_STACK_OVERFLOW_URLS[source.role],
                expected_license_urls=_LICENSE_TERMS_URLS["stack-overflow"],
                _test_only_after_snapshot=_test_only_after_source_snapshot,
            ) as snapshot_source,
            gzip.open(snapshot_source.path, "rt", encoding="utf-8", newline="") as handle,
        ):
            for within_file_ordinal, line in enumerate(handle):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                fields = stripped.split()
                if len(fields) != 3:
                    rejected["malformed-record"] += 1
                    continue
                try:
                    source_id, target_id, unix_timestamp = (int(value) for value in fields)
                    if source_id <= 0 or target_id <= 0 or unix_timestamp < 0:
                        raise ValueError
                    timestamp = datetime.fromtimestamp(unix_timestamp, tz=UTC)
                except (OverflowError, ValueError):
                    rejected["malformed-record"] += 1
                    continue
                if source_id == target_id:
                    rejected["self-loop"] += 1
                    continue
                emit(
                    CanonicalRawEvent(
                        schema_version=CANONICAL_RAW_EVENT_SCHEMA,
                        timestamp_utc=_canonical_instant(timestamp),
                        source_file_ordinal=role_ordinals[source.role],
                        within_file_ordinal=within_file_ordinal,
                        canonical_source_id=f"stack-overflow:user:{source_id:020d}",
                        canonical_target_id=f"stack-overflow:user:{target_id:020d}",
                        source_event_type=source.role,
                    )
                )
        receipts.append(
            _acquisition_receipt(
                dataset_id="stack-overflow",
                source=source,
                rejected=rejected,
            )
        )
    if event_sink is None:
        events.sort(
            key=lambda event: (
                event.timestamp_utc,
                event.source_file_ordinal,
                event.within_file_ordinal,
            )
        )
    receipts.sort(key=lambda receipt: role_ordinals[receipt.role])
    return tuple(events), tuple(receipts)


def _parse_mediawiki_timestamp(value: str) -> datetime:
    normalized = value.strip().replace(" ", "T")
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    if parsed.utcoffset() != UTC.utcoffset(parsed):
        parsed = parsed.astimezone(UTC)
    return parsed


def _simplewiki_events(
    sources: Sequence[LocalSourceObject],
    *,
    event_sink: Callable[[CanonicalRawEvent], None] | None = None,
    _test_only_after_source_snapshot: _SourceSnapshotObserver | None = None,
) -> tuple[tuple[CanonicalRawEvent, ...], tuple[AcquisitionReceipt, ...]]:
    if len(sources) != 1 or sources[0].role != "history":
        raise ValueError("Simplewiki requires exactly one history source object")
    source = sources[0]
    rejected: Counter[str] = Counter()
    events: list[CanonicalRawEvent] = []
    emit = events.append if event_sink is None else event_sink
    saw_record = False
    with (
        _verified_source_snapshot(
            source,
            expected_url=_SIMPLEWIKI_URL,
            expected_license_urls=_LICENSE_TERMS_URLS["simplewiki-2026-07"],
            _test_only_after_snapshot=_test_only_after_source_snapshot,
        ) as snapshot_source,
        bz2.open(snapshot_source.path, "rt", encoding="utf-8", newline="") as handle,
    ):
        for within_file_ordinal, line in enumerate(handle):
            saw_record = True
            fields = line.rstrip("\r\n").split("\t")
            if len(fields) != _MEDIAWIKI_HISTORY_FIELD_COUNT:
                if within_file_ordinal == 0:
                    raise ValueError(
                        "Simplewiki dump does not match the frozen headerless 78-column schema"
                    )
                rejected["malformed-record"] += 1
                continue
            if fields[_MEDIAWIKI_HISTORY_INDEX["wiki_db"]] != "simplewiki":
                if within_file_ordinal == 0:
                    raise ValueError(
                        "Simplewiki dump does not match the frozen headerless 78-column schema"
                    )
                rejected["wrong-wiki-database"] += 1
                continue
            if (
                fields[_MEDIAWIKI_HISTORY_INDEX["event_entity"]] != "revision"
                or fields[_MEDIAWIKI_HISTORY_INDEX["event_type"]] != "create"
            ):
                rejected["non-revision-create"] += 1
                continue
            if fields[_MEDIAWIKI_HISTORY_INDEX["page_namespace_historical"]] != "0":
                rejected["non-main-namespace"] += 1
                continue
            identity_flags = (
                fields[_MEDIAWIKI_HISTORY_INDEX["event_user_is_anonymous"]],
                fields[_MEDIAWIKI_HISTORY_INDEX["event_user_is_temporary"]],
                fields[_MEDIAWIKI_HISTORY_INDEX["event_user_is_permanent"]],
            )
            if any(value not in {"true", "false"} for value in identity_flags):
                rejected["malformed-identity-flags"] += 1
                continue
            if identity_flags != ("false", "false", "true"):
                rejected["non-permanent-contributor"] += 1
                continue
            try:
                page_id = int(fields[_MEDIAWIKI_HISTORY_INDEX["page_id"]])
                user_id = int(fields[_MEDIAWIKI_HISTORY_INDEX["event_user_id"]])
                if page_id <= 0 or user_id <= 0:
                    raise ValueError
            except (TypeError, ValueError):
                rejected["missing-or-invalid-identity"] += 1
                continue
            try:
                timestamp = _parse_mediawiki_timestamp(
                    fields[_MEDIAWIKI_HISTORY_INDEX["event_timestamp"]]
                )
            except (TypeError, ValueError):
                rejected["invalid-timestamp"] += 1
                continue
            emit(
                CanonicalRawEvent(
                    schema_version=CANONICAL_RAW_EVENT_SCHEMA,
                    timestamp_utc=_canonical_instant(timestamp),
                    source_file_ordinal=0,
                    within_file_ordinal=within_file_ordinal,
                    canonical_source_id=f"wiki:page:{page_id:020d}",
                    canonical_target_id=f"wiki:user:{user_id:020d}",
                    source_event_type="revision-create",
                )
            )
    if not saw_record:
        raise ValueError("Simplewiki dump must contain at least one physical record")
    receipt = _acquisition_receipt(
        dataset_id="simplewiki-2026-07",
        source=source,
        rejected=rejected,
    )
    if event_sink is None:
        events.sort(
            key=lambda event: (
                event.timestamp_utc,
                event.source_file_ordinal,
                event.within_file_ordinal,
            )
        )
    return tuple(events), (receipt,)


def _positive_int(value: object) -> int:
    if isinstance(value, bool):
        raise ValueError
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and value.isascii() and value.isdigit():
        parsed = int(value)
    else:
        raise ValueError
    if parsed <= 0:
        raise ValueError
    return parsed


class _NonexistentNYCLocalTime(ValueError):
    """A naive wall time that does not exist in America/New_York."""


def _nyc_local_datetime(value: object) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        parsed = datetime.fromisoformat(value.strip())
    else:
        raise ValueError
    nyc = ZoneInfo("America/New_York")
    if parsed.tzinfo is None:
        localized = parsed.replace(tzinfo=nyc, fold=0)
        round_trip = localized.astimezone(UTC).astimezone(nyc)
        if round_trip.replace(tzinfo=None) != parsed:
            raise _NonexistentNYCLocalTime("nonexistent America/New_York local time")
        return localized
    return parsed.astimezone(nyc)


def _nyc_bin_of_week(timestamp: datetime) -> int:
    return timestamp.weekday() * 96 + timestamp.hour * 4 + timestamp.minute // 15


def _validate_publication_parquet_runtime(
    *,
    implementation_name: object,
    python_version: object,
    pyarrow_version: object,
    platform_name: object,
    machine: object,
    platform_tag: object,
    timezone_tzif_sha256: object,
) -> dict[str, object]:
    """Require the exact parser runtime frozen by the publication protocol."""

    supported_platform = (platform_name == "darwin" and machine in {"arm64", "x86_64"}) or (
        platform_name == "linux" and machine in {"aarch64", "x86_64"}
    )
    if (
        type(implementation_name) is not str
        or implementation_name != "cpython"
        or type(python_version) is not tuple
        or python_version != _PUBLICATION_PYTHON_VERSION
        or type(pyarrow_version) is not str
        or pyarrow_version != "25.0.1"
        or type(platform_name) is not str
        or type(machine) is not str
        or not supported_platform
        or type(platform_tag) is not str
        or not platform_tag
        or type(timezone_tzif_sha256) is not str
        or timezone_tzif_sha256 != _NYC_TZIF_SHA256
    ):
        raise RuntimeError(
            "NYC TLC parsing requires the frozen NYC TLC parser runtime: "
            "CPython 3.12.13, pyarrow 25.0.1, a locked binary-wheel platform, and the "
            "frozen America/New_York TZif bytes"
        )
    return {
        "schema_version": PARSER_RUNTIME_SCHEMA,
        "container_image_digest": None,
        "implementation_name": implementation_name,
        "python_version": ".".join(str(part) for part in python_version),
        "pyarrow_version": pyarrow_version,
        "platform_name": platform_name,
        "machine": machine,
        "platform_tag": platform_tag,
        "timezone_key": "America/New_York",
        "timezone_tzif_sha256": timezone_tzif_sha256,
    }


def _nyc_tzif_sha256() -> str:
    """Resolve the system TZif bytes and reject ambiguity or drift."""

    observed: set[str] = set()
    for root in TZPATH:
        candidate = Path(root) / "America" / "New_York"
        if not candidate.exists():
            continue
        observed.add(hashlib.sha256(_read_regular_file_no_follow(candidate)).hexdigest())
    if observed != {_NYC_TZIF_SHA256}:
        raise RuntimeError(
            "America/New_York TZif identity does not match the publication-frozen bytes"
        )
    return _NYC_TZIF_SHA256


def _current_publication_parser_runtime_identity(pyarrow_version: object) -> dict[str, object]:
    return _validate_publication_parquet_runtime(
        implementation_name=sys.implementation.name,
        python_version=(sys.version_info.major, sys.version_info.minor, sys.version_info.micro),
        pyarrow_version=pyarrow_version,
        platform_name=sys.platform,
        machine=platform.machine(),
        platform_tag=sysconfig.get_platform(),
        timezone_tzif_sha256=_nyc_tzif_sha256(),
    )


def _normalization_contract_payload(
    dataset_id: str,
    *,
    config: _TraceConfig,
) -> dict[str, object]:
    contract = dict(_NORMALIZATION_CONTRACTS[dataset_id])
    if dataset_id != "nyc-tlc-yellow-2022":
        return contract
    if config.allow_fixture_tlc_csv:
        contract["parser_runtime_identity"] = {
            "schema_version": PARSER_RUNTIME_SCHEMA,
            "verification_mode": "test-only-csv-fixture-no-publication-authority",
        }
        return contract
    try:
        import pyarrow  # type: ignore[import-not-found]
    except ModuleNotFoundError as error:
        raise RuntimeError(
            "NYC TLC Parquet parsing requires pyarrow; no download or format fallback is permitted"
        ) from error
    contract["parser_runtime_identity"] = _current_publication_parser_runtime_identity(
        getattr(pyarrow, "__version__", None)
    )
    return contract


def _iter_nyc_trip_rows(
    source: LocalSourceObject, *, config: _TraceConfig
) -> Iterator[Mapping[str, object]]:
    if config.allow_fixture_tlc_csv:
        with source.path.open("r", encoding="utf-8", newline="") as handle:
            yield from csv.DictReader(handle)
        return
    try:
        import pyarrow  # type: ignore[import-not-found]
        import pyarrow.parquet as parquet  # type: ignore[import-not-found]
    except ModuleNotFoundError as error:
        raise RuntimeError(
            "NYC TLC Parquet parsing requires pyarrow; no download or format fallback is permitted"
        ) from error
    _current_publication_parser_runtime_identity(getattr(pyarrow, "__version__", None))
    columns = (
        "tpep_pickup_datetime",
        "tpep_dropoff_datetime",
        "PULocationID",
        "DOLocationID",
    )
    parquet_file = parquet.ParquetFile(source.path)
    for batch in parquet_file.iter_batches(batch_size=65_536, columns=columns):
        yield from batch.to_pylist()


def _iter_verified_nyc_trip_rows(
    source: LocalSourceObject,
    *,
    config: _TraceConfig,
    _test_only_after_source_snapshot: _SourceSnapshotObserver | None,
) -> Iterator[Mapping[str, object]]:
    with _verified_source_snapshot(
        source,
        expected_url=_NYC_TRIP_URLS[source.role],
        expected_license_urls=_LICENSE_TERMS_URLS["nyc-tlc-yellow-2022"],
        _test_only_after_snapshot=_test_only_after_source_snapshot,
    ) as snapshot_source:
        yield from _iter_nyc_trip_rows(snapshot_source, config=config)


def _nyc_receipt(source: LocalSourceObject, rejected: Mapping[str, int]) -> AcquisitionReceipt:
    return _acquisition_receipt(
        dataset_id="nyc-tlc-yellow-2022",
        source=source,
        rejected=rejected,
    )


def _nyc_events(
    sources: Sequence[LocalSourceObject],
    *,
    config: _TraceConfig,
    event_sink: Callable[[CanonicalRawEvent], None] | None = None,
    _test_only_after_source_snapshot: _SourceSnapshotObserver | None = None,
) -> tuple[tuple[CanonicalRawEvent, ...], tuple[AcquisitionReceipt, ...]]:
    by_role: dict[str, LocalSourceObject] = {}
    for source in sources:
        if source.role in by_role:
            raise ValueError(f"duplicate NYC TLC source role: {source.role}")
        by_role[source.role] = source
    lookup = by_role.get("zone-lookup")
    if lookup is None:
        raise ValueError("NYC TLC sources require the frozen taxi-zone lookup")
    valid_zones: set[int] = set()
    lookup_rejected: Counter[str] = Counter()
    with (
        _verified_source_snapshot(
            lookup,
            expected_url=_NYC_ZONE_URL,
            expected_license_urls=_LICENSE_TERMS_URLS["nyc-tlc-yellow-2022"],
            _test_only_after_snapshot=_test_only_after_source_snapshot,
        ) as snapshot_lookup,
        snapshot_lookup.path.open("r", encoding="utf-8-sig", newline="") as handle,
    ):
        reader = csv.DictReader(handle)
        if "LocationID" not in (reader.fieldnames or ()):
            raise ValueError("taxi-zone lookup missing LocationID")
        for row in reader:
            try:
                valid_zones.add(_positive_int(row["LocationID"]))
            except (KeyError, ValueError):
                lookup_rejected["invalid-zone-record"] += 1
    if not valid_zones:
        raise ValueError("taxi-zone lookup contains no valid zones")

    events: list[CanonicalRawEvent] = []
    emit = events.append if event_sink is None else event_sink
    receipts_by_role: dict[str, AcquisitionReceipt] = {
        "zone-lookup": _nyc_receipt(lookup, lookup_rejected)
    }
    trip_roles = sorted(role for role in by_role if role != "zone-lookup")
    if not trip_roles:
        raise ValueError("NYC TLC sources require at least one monthly trip object")
    for role in trip_roles:
        if role not in _NYC_TRIP_URLS:
            raise ValueError(f"unknown NYC TLC source role: {role!r}")
        source = by_role[role]
        rejected: Counter[str] = Counter()
        month = int(role[-2:])
        rows = _iter_verified_nyc_trip_rows(
            source,
            config=config,
            _test_only_after_source_snapshot=_test_only_after_source_snapshot,
        )
        for within_file_ordinal, row in enumerate(rows):
            try:
                pickup = _nyc_local_datetime(row["tpep_pickup_datetime"])
                dropoff = _nyc_local_datetime(row["tpep_dropoff_datetime"])
            except _NonexistentNYCLocalTime:
                rejected["nonexistent-local-time"] += 1
                continue
            except (KeyError, TypeError, ValueError):
                rejected["invalid-timestamp"] += 1
                continue
            if pickup.year != 2022 or pickup.month != month:
                rejected["pickup-outside-source-month"] += 1
                continue
            if dropoff.astimezone(UTC) < pickup.astimezone(UTC):
                rejected["dropoff-before-pickup"] += 1
                continue
            try:
                pickup_zone = _positive_int(row["PULocationID"])
                dropoff_zone = _positive_int(row["DOLocationID"])
            except (KeyError, ValueError):
                rejected["invalid-zone"] += 1
                continue
            if pickup_zone not in valid_zones or dropoff_zone not in valid_zones:
                rejected["invalid-zone"] += 1
                continue
            emit(
                CanonicalRawEvent(
                    schema_version=CANONICAL_RAW_EVENT_SCHEMA,
                    timestamp_utc=_canonical_instant(pickup),
                    source_file_ordinal=month - 1,
                    within_file_ordinal=within_file_ordinal,
                    canonical_source_id=(
                        f"nyc:pickup:zone:{pickup_zone:03d}:bin:{_nyc_bin_of_week(pickup):03d}"
                    ),
                    canonical_target_id=(
                        f"nyc:dropoff:zone:{dropoff_zone:03d}:bin:{_nyc_bin_of_week(dropoff):03d}"
                    ),
                    source_event_type="yellow-trip",
                )
            )
        receipts_by_role[role] = _nyc_receipt(source, rejected)
    if event_sink is None:
        events.sort(
            key=lambda event: (
                event.timestamp_utc,
                event.source_file_ordinal,
                event.within_file_ordinal,
            )
        )
    receipt_roles = (*sorted(trip_roles), "zone-lookup")
    return tuple(events), tuple(receipts_by_role[role] for role in receipt_roles)


def _read_canonical_raw_events(
    dataset_id: str,
    sources: Sequence[LocalSourceObject],
    *,
    config: _TraceConfig,
    event_sink: Callable[[CanonicalRawEvent], None] | None = None,
    _test_only_after_source_snapshot: _SourceSnapshotObserver | None = None,
) -> CanonicalRawEventBatch:
    if type(config) is not _TraceConfig:
        raise TypeError("config must be an exact _TraceConfig")
    if not isinstance(sources, (tuple, list)) or not sources:
        raise ValueError("sources must be a nonempty sequence")
    required_roles = _required_roles(dataset_id)
    observed_roles = tuple(source.role for source in sources)
    if len(observed_roles) != len(required_roles) or set(observed_roles) != required_roles:
        raise ValueError(
            "canonical dataset preparation requires the exact frozen source roles; "
            f"missing={sorted(required_roles - set(observed_roles))}, "
            f"extra={sorted(set(observed_roles) - required_roles)}"
        )
    if dataset_id == "stack-overflow":
        dataset_release = _DATASET_RELEASES[dataset_id]
        events, receipts = _stack_overflow_events(
            sources,
            event_sink=event_sink,
            _test_only_after_source_snapshot=_test_only_after_source_snapshot,
        )
    elif dataset_id == "simplewiki-2026-07":
        dataset_release = _DATASET_RELEASES[dataset_id]
        events, receipts = _simplewiki_events(
            sources,
            event_sink=event_sink,
            _test_only_after_source_snapshot=_test_only_after_source_snapshot,
        )
    elif dataset_id == "nyc-tlc-yellow-2022":
        dataset_release = _DATASET_RELEASES[dataset_id]
        events, receipts = _nyc_events(
            sources,
            config=config,
            event_sink=event_sink,
            _test_only_after_source_snapshot=_test_only_after_source_snapshot,
        )
    else:
        raise ValueError(f"unsupported primary dataset: {dataset_id!r}")
    return CanonicalRawEventBatch(
        dataset_id=dataset_id,
        dataset_release=dataset_release,
        events=events,
        receipts=receipts,
    )


def _canonical_json_bytes(value: object) -> bytes:
    serialized = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return (serialized + "\n").encode("utf-8")


def _publication_query_vector_payload(
    *,
    dataset_id: str,
    dataset_release: str,
    semantics: str,
    source_partition: int,
    mapping_sha256: str,
    length: int,
) -> dict[str, object]:
    """Build one outcome-independent ternary vector for a paired analysis unit."""

    domain = _canonical_json_bytes(
        {
            "dataset_id": dataset_id,
            "dataset_release": dataset_release,
            "mapping_sha256": mapping_sha256,
            "length": length,
            "schema_version": PUBLICATION_QUERY_VECTOR_SCHEMA,
            "seed": PUBLICATION_QUERY_VECTOR_SEED,
            "semantics": semantics,
            "source_partition": source_partition,
        }
    )
    values: list[int] = []
    for coordinate in range(length):
        if coordinate == 0:
            values.append(1)
            continue
        if coordinate == length - 1:
            values.append(-1)
            continue
        attempt = 0
        while True:
            sample = hashlib.shake_256(
                b"dynamic-cssc-publication-query-coordinate-v1\0"
                + domain
                + coordinate.to_bytes(8, "big")
                + attempt.to_bytes(8, "big")
            ).digest(1)[0]
            if sample < 255:
                values.append((-1, 0, 1)[sample % 3])
                break
            attempt += 1
    return {
        "schema_version": PUBLICATION_QUERY_VECTOR_SCHEMA,
        "dataset_id": dataset_id,
        "dataset_release": dataset_release,
        "semantics": semantics,
        "source_partition": source_partition,
        "mapping_sha256": mapping_sha256,
        "length": length,
        "seed": PUBLICATION_QUERY_VECTOR_SEED,
        "coefficient_bound": 1,
        "generation": "shake256-per-coordinate-rejection-sampling",
        "reuse_scope": "one-vector-per-paired-analysis-unit-all-query-arrivals",
        "values": values,
    }


def _repository_provenance_payload(snapshot: _RepositorySnapshot) -> dict[str, object]:
    if type(snapshot) is not _RepositorySnapshot:
        raise TypeError("repository_snapshot must be an exact _RepositorySnapshot")
    if not _GIT_OBJECT_ID.fullmatch(snapshot.source_git_sha):
        raise ValueError("repository snapshot source_git_sha must be a canonical Git object ID")
    expected_paths = set(_PUBLICATION_BEHAVIOR_PATHS)
    if set(snapshot.behavior_source_blob_sha256) != expected_paths:
        raise ValueError("repository snapshot must bind the exact frozen behavior source paths")
    behavior_digests = dict(sorted(snapshot.behavior_source_blob_sha256.items()))
    if any(
        not isinstance(path, str) or not isinstance(digest, str) or not _SHA256.fullmatch(digest)
        for path, digest in behavior_digests.items()
    ):
        raise ValueError("repository snapshot behavior digests must be lowercase SHA-256 values")
    if snapshot.verification_mode not in {
        "hardened-trace-role-git-object-worktree-v1",
        "test-only-fixed-repository-snapshot-v1",
    }:
        raise ValueError("repository snapshot verification mode is not recognized")
    core: dict[str, object] = {
        "schema_version": REPOSITORY_PROVENANCE_SCHEMA,
        "source_git_sha": snapshot.source_git_sha,
        "behavior_source_blob_sha256": behavior_digests,
        "verification_mode": snapshot.verification_mode,
    }
    return {
        **core,
        "repository_provenance_sha256": hashlib.sha256(_canonical_json_bytes(core)).hexdigest(),
    }


def _receipt_payload(
    receipt: AcquisitionReceipt,
    *,
    repository_provenance: Mapping[str, object],
) -> dict[str, object]:
    return {
        "schema_version": receipt.schema_version,
        "dataset_id": receipt.dataset_id,
        "dataset_release": receipt.dataset_release,
        "source_git_sha": repository_provenance["source_git_sha"],
        "behavior_source_blob_sha256": dict(
            repository_provenance["behavior_source_blob_sha256"]  # type: ignore[arg-type]
        ),
        "repository_provenance_sha256": repository_provenance["repository_provenance_sha256"],
        "role": receipt.role,
        "source_url": receipt.source_url,
        "final_url": receipt.final_url,
        "http_status": receipt.http_status,
        "media_type": receipt.media_type,
        "retrieval_utc": receipt.retrieval_utc,
        "byte_count": receipt.byte_count,
        "http_etag": receipt.http_etag,
        "http_last_modified": receipt.http_last_modified,
        "local_sha256": receipt.local_sha256,
        "publisher_sha256": receipt.publisher_sha256,
        "license_terms_set_sha256": receipt.license_terms_set_sha256,
        "license_terms_objects": [dict(item) for item in receipt.license_terms_objects],
        "attribution_text": receipt.attribution_text,
        "redistribution_policy": receipt.redistribution_policy,
        "rejected_event_counts": dict(receipt.rejected_event_counts),
    }


def _transition_payload(record: PublicationTransition) -> dict[str, object]:
    def event_payload(event: TransitionEventProvenance) -> dict[str, object]:
        return {
            "canonical_raw_event_ordinal": event.canonical_raw_event_ordinal,
            "source_timestamp_utc": event.source_timestamp_utc,
            "source_file_ordinal": event.source_file_ordinal,
            "within_file_ordinal": event.within_file_ordinal,
            "source_event_type": event.source_event_type,
        }

    return {
        "schema_version": record.schema_version,
        "dataset_id": record.dataset_id,
        "dataset_release": record.dataset_release,
        "semantics": record.semantics,
        "source_partition": record.source_partition,
        "repository_provenance_sha256": record.repository_provenance_sha256,
        "accepted_event_ordinal": record.accepted_event_ordinal,
        "transition_ordinal": record.transition_ordinal,
        "transition_cause": record.transition_cause,
        "trigger_event": event_payload(record.trigger_event),
        "subject_event": event_payload(record.subject_event),
        "logical_time_numerator": record.logical_time_numerator,
        "logical_time_denominator": record.logical_time_denominator,
        "row_index": record.row_index,
        "column_index": record.column_index,
        "operation": record.operation,
        "before": record.before,
        "after": record.after,
    }


def _raw_event_payload(event: CanonicalRawEvent) -> dict[str, object]:
    return {
        "schema_version": event.schema_version,
        "timestamp_utc": event.timestamp_utc,
        "source_file_ordinal": event.source_file_ordinal,
        "within_file_ordinal": event.within_file_ordinal,
        "canonical_source_id": event.canonical_source_id,
        "canonical_target_id": event.canonical_target_id,
        "source_event_type": event.source_event_type,
    }


def _required_roles(dataset_id: str) -> frozenset[str]:
    if dataset_id == "stack-overflow":
        return frozenset(_STACK_OVERFLOW_URLS)
    if dataset_id == "simplewiki-2026-07":
        return frozenset({"history"})
    if dataset_id == "nyc-tlc-yellow-2022":
        return frozenset({*_NYC_TRIP_URLS, "zone-lookup"})
    raise ValueError(f"unsupported primary dataset: {dataset_id!r}")


def _validate_request(request: _LocalTraceRequest, config: _TraceConfig) -> None:
    if type(request) is not _LocalTraceRequest:
        raise TypeError("request must be an exact _LocalTraceRequest")
    if request.semantics not in {"T1", "T2"}:
        raise ValueError("semantics must be exactly T1 or T2")
    if type(request.source_partition) is not int or not (
        0 <= request.source_partition < config.source_partitions
    ):
        raise ValueError("source_partition must be an integer in [0, 4]")
    if type(request.sources) is not tuple or not request.sources:
        raise ValueError("sources must be a nonempty tuple")
    roles = {source.role for source in request.sources}
    required = _required_roles(request.dataset_id)
    if roles != required:
        raise ValueError(
            "publication preparation requires the exact frozen source roles; "
            f"missing={sorted(required - roles)}, extra={sorted(roles - required)}"
        )


def _validate_config(config: _TraceConfig) -> None:
    integer_fields = (
        config.rows,
        config.cols,
        config.mapping_prefix_numerator,
        config.mapping_prefix_denominator,
        config.source_partitions,
        config.coefficient_cap,
        config.event_window_size,
        config.accepted_events_per_second,
        config.target_accepted_events,
        config.minimum_logical_changes,
        config.microbatch_cap,
        config.minimum_complete_window_lower_bound,
        config.maximum_row_nonzeros,
    )
    if any(type(value) is not int or value <= 0 for value in integer_fields):
        raise ValueError("trace configuration integers must be positive exact integers")
    if config.mapping_prefix_numerator >= config.mapping_prefix_denominator:
        raise ValueError("mapping prefix fraction must be between zero and one")
    if type(config.allow_fixture_tlc_csv) is not bool:
        raise ValueError("allow_fixture_tlc_csv must be boolean")


def _mapping_for_partition(
    batch: CanonicalRawEventBatch,
    *,
    total_event_count: int,
    prefix_events: Callable[[], Iterable[CanonicalRawEvent]],
    source_partition_id: int,
    config: _TraceConfig,
) -> tuple[dict[str, object], dict[str, int], dict[str, int], int, list[str]]:
    prefix_count = (
        total_event_count * config.mapping_prefix_numerator // config.mapping_prefix_denominator
    )
    row_counts: Counter[str] = Counter()
    for event in prefix_events():
        if (
            source_partition(batch.dataset_release, event.canonical_source_id)
            == source_partition_id
        ):
            row_counts[event.canonical_source_id] += 1
    observed_row_ids = sorted(row_counts, key=lambda identity: (-row_counts[identity], identity))[
        : config.rows
    ]
    selected_rows = set(observed_row_ids)
    column_counts: Counter[str] = Counter()
    for event in prefix_events():
        if (
            source_partition(batch.dataset_release, event.canonical_source_id)
            == source_partition_id
            and event.canonical_source_id in selected_rows
        ):
            column_counts[event.canonical_target_id] += 1
    observed_column_ids = sorted(
        column_counts, key=lambda identity: (-column_counts[identity], identity)
    )[: config.cols]
    return _mapping_from_observed_ids(
        batch,
        observed_row_ids=observed_row_ids,
        observed_column_ids=observed_column_ids,
        prefix_count=prefix_count,
        source_partition_id=source_partition_id,
        config=config,
    )


def _mapping_from_observed_ids(
    batch: CanonicalRawEventBatch,
    *,
    observed_row_ids: list[str],
    observed_column_ids: list[str],
    prefix_count: int,
    source_partition_id: int,
    config: _TraceConfig,
) -> tuple[dict[str, object], dict[str, int], dict[str, int], int, list[str]]:
    """Build the frozen mapping payload from already ranked bounded identities."""

    padding = config.cols - len(observed_column_ids)
    reserved_ids = [
        (f"reserved-empty-column:{batch.dataset_id}:partition-{source_partition_id}:{index:05d}")
        for index in range(padding)
    ]
    column_ids = [*observed_column_ids, *reserved_ids]
    mapping_core: dict[str, object] = {
        "schema_version": PUBLICATION_MAPPING_SCHEMA,
        "dataset_id": batch.dataset_id,
        "dataset_release": batch.dataset_release,
        "source_partition": source_partition_id,
        "canonical_id_serialization": "utf-8-ascii-prefixed-zero-padded-v1",
        "mapping_prefix_events": prefix_count,
        "row_ids": observed_row_ids,
        "column_ids": column_ids,
        "observed_column_count": len(observed_column_ids),
        "reserved_empty_column_count": padding,
    }
    mapping_digest = hashlib.sha256(_canonical_json_bytes(mapping_core)).hexdigest()
    mapping = {**mapping_core, "mapping_sha256": mapping_digest}
    reasons: list[str] = []
    if prefix_count == 0:
        reasons.append("mapping-prefix-empty")
    if len(observed_row_ids) != config.rows:
        reasons.append(f"insufficient-mapped-rows:{len(observed_row_ids)}/{config.rows}")
    # Reserved columns are semantic zero columns in the fixed publication
    # domain.  They remain present in the query vector and therefore retain
    # their full communication and cryptographic cost.  Their fraction is a
    # reported corpus characteristic, not an eligibility threshold.  Refuse
    # only a mapping with no observed target identity at all.
    if not observed_column_ids:
        reasons.append("no-observed-mapped-columns")
    row_index = {identity: index for index, identity in enumerate(observed_row_ids)}
    column_index = {identity: index for index, identity in enumerate(observed_column_ids)}
    return mapping, row_index, column_index, prefix_count, reasons


def _operation(before: int, after: int) -> str:
    if before == after:
        return "clipped-no-op"
    if before == 0:
        return "insert"
    if after == 0:
        return "delete"
    return "modify"


def _record_transition(
    *,
    batch: CanonicalRawEventBatch,
    semantics: str,
    source_partition_id: int,
    repository_provenance_sha256: str,
    trigger_event: CanonicalRawEvent,
    trigger_raw_event_ordinal: int,
    subject_event: CanonicalRawEvent,
    subject_raw_event_ordinal: int,
    accepted_event_ordinal: int,
    transition_ordinal: int,
    transition_cause: str,
    row_index: int,
    column_index: int,
    before: int,
    after: int,
    config: _TraceConfig,
) -> PublicationTransition:
    def provenance(
        event: CanonicalRawEvent,
        raw_event_ordinal: int,
    ) -> TransitionEventProvenance:
        return TransitionEventProvenance(
            canonical_raw_event_ordinal=raw_event_ordinal,
            source_timestamp_utc=event.timestamp_utc,
            source_file_ordinal=event.source_file_ordinal,
            within_file_ordinal=event.within_file_ordinal,
            source_event_type=event.source_event_type,
        )

    return PublicationTransition(
        schema_version=PUBLICATION_TRANSITION_SCHEMA,
        dataset_id=batch.dataset_id,
        dataset_release=batch.dataset_release,
        semantics=semantics,
        source_partition=source_partition_id,
        repository_provenance_sha256=repository_provenance_sha256,
        accepted_event_ordinal=accepted_event_ordinal,
        transition_ordinal=transition_ordinal,
        transition_cause=transition_cause,
        trigger_event=provenance(trigger_event, trigger_raw_event_ordinal),
        subject_event=provenance(subject_event, subject_raw_event_ordinal),
        logical_time_numerator=accepted_event_ordinal,
        logical_time_denominator=config.accepted_events_per_second,
        row_index=row_index,
        column_index=column_index,
        operation=_operation(before, after),
        before=before,
        after=after,
    )


def _transform_events(
    batch: CanonicalRawEventBatch,
    *,
    ordered_events: Iterable[tuple[int, CanonicalRawEvent]],
    semantics: str,
    source_partition_id: int,
    repository_provenance_sha256: str,
    row_index: Mapping[str, int],
    column_index: Mapping[str, int],
    config: _TraceConfig,
    accepted_event_limit: int | None,
    record_sink: Callable[[PublicationTransition], None] | None = None,
    retain_records: bool = True,
) -> _TransformResult:
    if accepted_event_limit is not None and (
        type(accepted_event_limit) is not int or accepted_event_limit <= 0
    ):
        raise ValueError("accepted_event_limit must be null or a positive exact integer")
    if record_sink is not None and not callable(record_sink):
        raise TypeError("record_sink must be callable or null")
    if type(retain_records) is not bool:
        raise TypeError("retain_records must be an exact boolean")
    filtered: Counter[str] = Counter()
    accepted_hasher = hashlib.sha256()
    source_event_type_counts: Counter[str] = Counter()
    raw_counts: Counter[tuple[int, int]] = Counter()
    active_nonzeros_by_row: Counter[int] = Counter()
    peak_row_nonzeros = 0
    records: list[PublicationTransition] = []
    event_window: deque[tuple[int, CanonicalRawEvent, int, int]] = deque()
    accepted_event_count = 0
    transition_record_count = 0
    operation_counts: Counter[str] = Counter()
    maximum_transition_group_size_observed = 0
    event_window_peak_groups = 0
    peak_live_coordinate_count = 0
    last_transition_group: int | None = None
    current_transition_group_size = 0

    def apply(
        *,
        trigger_event: CanonicalRawEvent,
        trigger_raw_ordinal: int,
        subject_event: CanonicalRawEvent,
        subject_raw_ordinal: int,
        accepted_ordinal: int,
        row: int,
        column: int,
        cause: str,
        transition_ordinal: int,
        delta: int,
    ) -> None:
        nonlocal current_transition_group_size
        nonlocal last_transition_group
        nonlocal maximum_transition_group_size_observed
        nonlocal peak_row_nonzeros
        nonlocal peak_live_coordinate_count
        nonlocal transition_record_count
        coordinate = (row, column)
        raw_before = raw_counts[coordinate]
        before = min(config.coefficient_cap, raw_before)
        raw_after = raw_before + delta
        if raw_after < 0:
            raise AssertionError("event-window count became negative")
        raw_counts[coordinate] = raw_after
        after = min(config.coefficient_cap, raw_after)
        if before == 0 and after > 0:
            active_nonzeros_by_row[row] += 1
        elif before > 0 and after == 0:
            active_nonzeros_by_row[row] -= 1
        if raw_after == 0:
            del raw_counts[coordinate]
        peak_live_coordinate_count = max(peak_live_coordinate_count, len(raw_counts))
        peak_row_nonzeros = max(peak_row_nonzeros, active_nonzeros_by_row[row])
        record = _record_transition(
            batch=batch,
            semantics=semantics,
            source_partition_id=source_partition_id,
            repository_provenance_sha256=repository_provenance_sha256,
            trigger_event=trigger_event,
            trigger_raw_event_ordinal=trigger_raw_ordinal,
            subject_event=subject_event,
            subject_raw_event_ordinal=subject_raw_ordinal,
            accepted_event_ordinal=accepted_ordinal,
            transition_ordinal=transition_ordinal,
            transition_cause=cause,
            row_index=row,
            column_index=column,
            before=before,
            after=after,
            config=config,
        )
        if record_sink is not None:
            record_sink(record)
        if retain_records:
            records.append(record)
        transition_record_count += 1
        operation_counts[record.operation] += 1
        if last_transition_group == accepted_ordinal:
            current_transition_group_size += 1
        else:
            last_transition_group = accepted_ordinal
            current_transition_group_size = 1
        maximum_transition_group_size_observed = max(
            maximum_transition_group_size_observed,
            current_transition_group_size,
        )

    for raw_ordinal, event in ordered_events:
        event_partition = source_partition(batch.dataset_release, event.canonical_source_id)
        if event_partition != source_partition_id:
            filtered["other-source-partition"] += 1
            continue
        if event.canonical_source_id not in row_index:
            filtered["unselected-source"] += 1
            continue
        if event.canonical_target_id not in column_index:
            filtered["unselected-target"] += 1
            continue
        if accepted_event_limit is not None and accepted_event_count == accepted_event_limit:
            filtered["after-target"] += 1
            continue
        accepted_ordinal = accepted_event_count
        accepted_event_count += 1
        row = row_index[event.canonical_source_id]
        column = column_index[event.canonical_target_id]
        accepted_hasher.update(_canonical_json_bytes(_raw_event_payload(event)))
        source_event_type_counts[event.source_event_type] += 1
        if semantics == "T2" and len(event_window) == config.event_window_size:
            expired_raw_ordinal, expired_event, expired_row, expired_column = event_window.popleft()
            apply(
                trigger_event=event,
                trigger_raw_ordinal=raw_ordinal,
                subject_event=expired_event,
                subject_raw_ordinal=expired_raw_ordinal,
                accepted_ordinal=accepted_ordinal,
                row=expired_row,
                column=expired_column,
                cause="expiry",
                transition_ordinal=0,
                delta=-1,
            )
        apply(
            trigger_event=event,
            trigger_raw_ordinal=raw_ordinal,
            subject_event=event,
            subject_raw_ordinal=raw_ordinal,
            accepted_ordinal=accepted_ordinal,
            row=row,
            column=column,
            cause="admission",
            transition_ordinal=1 if semantics == "T2" else 0,
            delta=1,
        )
        if semantics == "T2":
            event_window.append((raw_ordinal, event, row, column))
            event_window_peak_groups = max(event_window_peak_groups, len(event_window))
    return _TransformResult(
        records=tuple(records),
        filter_counts=dict(sorted(filtered.items())),
        peak_row_nonzeros=peak_row_nonzeros,
        accepted_raw_event_sha256=accepted_hasher.hexdigest(),
        source_event_type_counts=dict(sorted(source_event_type_counts.items())),
        accepted_event_count=accepted_event_count,
        transition_record_count=transition_record_count,
        operation_counts={
            operation: operation_counts[operation]
            for operation in ("insert", "modify", "delete", "clipped-no-op")
        },
        maximum_transition_group_size_observed=maximum_transition_group_size_observed,
        event_window_peak_groups=event_window_peak_groups,
        peak_live_coordinate_count=peak_live_coordinate_count,
    )


def _prepare_verified_publication_trace(
    acquisition: _VerifiedAcquisitionInput,
    *,
    config: _TraceConfig,
    repository_snapshot: _RepositorySnapshot,
) -> PublicationTraceBundle:
    """Transform one already verified acquisition capability into a trace bundle."""

    if type(acquisition) is not _VerifiedAcquisitionInput:
        raise TypeError("acquisition must be an exact _VerifiedAcquisitionInput")
    if type(config) is not _TraceConfig:
        raise TypeError("config must be an exact _TraceConfig")
    request = acquisition.request
    acquisition_binding = acquisition.binding
    _validate_config(config)
    _validate_request(request, config)
    repository_provenance = _repository_provenance_payload(repository_snapshot)
    repository_provenance_sha256 = str(repository_provenance["repository_provenance_sha256"])
    with tempfile.TemporaryDirectory(prefix="dynamic-cssc-publication-trace-") as temporary:
        event_store = _CanonicalEventStore(Path(temporary) / "canonical-events.sqlite3")
        try:
            batch = _read_canonical_raw_events(
                request.dataset_id,
                request.sources,
                config=config,
                event_sink=event_store.add,
            )
            event_store.finalize()
            total_event_count = event_store.count
            mapping, row_index, column_index, prefix_count, eligibility_reasons = (
                event_store.mapping_for_partition(
                    batch,
                    total_event_count=total_event_count,
                    source_partition_id=request.source_partition,
                    config=config,
                )
            )
            transform = _transform_events(
                batch,
                ordered_events=enumerate(
                    event_store.ordered_events(offset=prefix_count),
                    start=prefix_count,
                ),
                semantics=request.semantics,
                source_partition_id=request.source_partition,
                repository_provenance_sha256=repository_provenance_sha256,
                row_index=row_index,
                column_index=column_index,
                config=config,
                accepted_event_limit=config.target_accepted_events,
            )
        finally:
            event_store.close()
    records = transform.records
    filtered_counts = transform.filter_counts
    peak_row_nonzeros = transform.peak_row_nonzeros
    accepted_events = len({record.accepted_event_ordinal for record in records})
    logical_changes = sum(record.operation != "clipped-no-op" for record in records)
    clipped_noops = len(records) - logical_changes
    maximum_atomic_group_size = 2 if request.semantics == "T2" else 1
    maximum_transitions_per_microbatch_window = (
        config.microbatch_cap + maximum_atomic_group_size - 1
    )
    complete_window_lower_bound = logical_changes // maximum_transitions_per_microbatch_window
    if accepted_events != config.target_accepted_events:
        eligibility_reasons.append(
            f"accepted-event-target-not-reached:{accepted_events}/{config.target_accepted_events}"
        )
    if logical_changes < config.minimum_logical_changes:
        eligibility_reasons.append(
            f"logical-change-minimum-not-reached:{logical_changes}/{config.minimum_logical_changes}"
        )
    if complete_window_lower_bound < config.minimum_complete_window_lower_bound:
        eligibility_reasons.append(
            "complete-window-lower-bound-minimum-not-reached:"
            f"{complete_window_lower_bound}/{config.minimum_complete_window_lower_bound}"
        )
    if peak_row_nonzeros > config.maximum_row_nonzeros:
        eligibility_reasons.append(
            f"maximum-row-nonzeros-exceeded:{peak_row_nonzeros}/{config.maximum_row_nonzeros}"
        )
    trace_payloads = [_transition_payload(record) for record in records]
    trace_jsonl_bytes = b"".join(_canonical_json_bytes(payload) for payload in trace_payloads)
    query_vector_payload = _publication_query_vector_payload(
        dataset_id=batch.dataset_id,
        dataset_release=batch.dataset_release,
        semantics=request.semantics,
        source_partition=request.source_partition,
        mapping_sha256=str(mapping["mapping_sha256"]),
        length=config.cols,
    )
    query_vector_bytes = _canonical_json_bytes(query_vector_payload)
    query_vector_sha256 = hashlib.sha256(query_vector_bytes).hexdigest()
    forced_boundary_entries = {"0": 1}
    if config.cols > 1:
        forced_boundary_entries[str(config.cols - 1)] = -1
    manifest: dict[str, object] = {
        "schema_version": PUBLICATION_TRACE_MANIFEST_SCHEMA,
        "protocol_version": "2.1b",
        "artifact_policy": "derived-trace-and-download-by-source-only",
        "dataset_id": batch.dataset_id,
        "dataset_release": batch.dataset_release,
        "semantics": request.semantics,
        "source_partition": request.source_partition,
        "repository_provenance": repository_provenance,
        "normalization_contract": _normalization_contract_payload(
            batch.dataset_id,
            config=config,
        ),
        "ordering": ["normalized-utc", "source-file-ordinal", "within-file-ordinal"],
        "logical_clock": {
            "accepted_events_per_second": config.accepted_events_per_second,
            "first_accepted_event_tick": 0,
            "historical_time_is_provenance_only": True,
        },
        "frozen_contract": {
            "rows": config.rows,
            "cols": config.cols,
            "mapping_prefix_numerator": config.mapping_prefix_numerator,
            "mapping_prefix_denominator": config.mapping_prefix_denominator,
            "mapping_tie_break": "canonical-id-ascending",
            "source_partition_rule": (
                "big-endian-SHA256(dataset_release||canonical_source_id)-mod-5"
            ),
            "reserved_column_padding_max_fraction": "1/10",
            "coefficient_cap": config.coefficient_cap,
            "event_window_size": config.event_window_size,
            "t2_transition_order": "expiry-before-admission",
            "t2_expiry_event_provenance": (
                "trigger-event-is-incoming-raw-event;subject-event-is-expired-raw-event"
            ),
            "target_accepted_events": config.target_accepted_events,
            "minimum_logical_changes": config.minimum_logical_changes,
            "microbatch_cap": config.microbatch_cap,
            "microbatch_cap_unit": "emitted-logical-set-transitions",
            "atomic_transition_group_policy": "accepted-event-group-never-split",
            "maximum_atomic_group_size": maximum_atomic_group_size,
            "maximum_transitions_per_microbatch_window": (
                maximum_transitions_per_microbatch_window
            ),
            "minimum_complete_window_lower_bound": (config.minimum_complete_window_lower_bound),
            "complete_publication_window_count_rule": (
                "floor(emitted_logical_changes/maximum-transitions-per-atomic-window)-"
                "conservative-lower-bound"
            ),
            "query_arrival_schedule": {
                "schema_version": "dynamic-cssc-query-arrival-schedule-v1",
                "rho_denominator_kind": "accepted-raw-event",
                "accepted_event_ordinal_origin": 0,
                "cumulative_query_rule": "floor(N*rho)",
                "grouping_key": "accepted_event_ordinal",
                "within_group_order": "transition_ordinal-ascending",
                "query_placement": "after-complete-group",
                "logical_tick_policy": "one-tick-after-every-complete-accepted-event-group",
                "scheduled_event_order": "set-transitions-then-tick-then-queries",
                "clipped_noop_policy": "counts-in-denominator-emits-tick-no-set",
            },
            "query_vector_generation": {
                "schema_version": PUBLICATION_QUERY_VECTOR_SCHEMA,
                "seed": PUBLICATION_QUERY_VECTOR_SEED,
                "length": config.cols,
                "coefficient_bound": 1,
                "generation": "shake256-per-coordinate-rejection-sampling",
                "forced_boundary_entries": forced_boundary_entries,
                "reuse_scope": "one-vector-per-paired-analysis-unit-all-query-arrivals",
                "evaluation_query_plaintext_public": True,
                "query_confidentiality_evidence_allowed": False,
                "security_randomness_claim_allowed": False,
                "query_distribution_claim_allowed": False,
            },
            "maximum_row_nonzeros": config.maximum_row_nonzeros,
            "evaluation_window_split": {
                "warmup_numerator": 1,
                "tuning_numerator": 3,
                "held_out_numerator": 6,
                "denominator": 10,
                "state_reset_between_splits": False,
            },
        },
        "acquisition_binding": dict(acquisition_binding),
        "acquisition_receipts": [
            _receipt_payload(receipt, repository_provenance=repository_provenance)
            for receipt in batch.receipts
        ],
        "schema_valid_raw_events": total_event_count,
        "mapping": mapping,
        "filter_counts": filtered_counts,
        "accepted_raw_event_sha256": transform.accepted_raw_event_sha256,
        "source_event_type_counts": transform.source_event_type_counts,
        "operation_counts": {
            operation: sum(record.operation == operation for record in records)
            for operation in ("insert", "modify", "delete", "clipped-no-op")
        },
        "trace": {
            "accepted_raw_events": accepted_events,
            "clipped_noops": clipped_noops,
            "complete_publication_window_lower_bound": complete_window_lower_bound,
            "logical_changes": logical_changes,
            "target_reached": accepted_events == config.target_accepted_events,
            "transition_records": len(records),
        },
        "realized_bounds": {
            "coefficient_min": 0,
            "coefficient_max": max((record.after for record in records), default=0),
            "peak_row_nonzeros": peak_row_nonzeros,
        },
        "query_vector": {
            "schema_version": PUBLICATION_QUERY_VECTOR_SCHEMA,
            "filename": "publication-query-vector.json",
            "length": config.cols,
            "query_vector_sha256": query_vector_sha256,
        },
        "trace_jsonl_sha256": hashlib.sha256(trace_jsonl_bytes).hexdigest(),
        "eligibility": {
            "eligible": not eligibility_reasons,
            "failure_reasons": eligibility_reasons,
            "replacement_allowed": False,
        },
    }
    manifest_bytes = _canonical_json_bytes(manifest)
    checksums = MappingProxyType(
        {
            "publication-trace.jsonl": hashlib.sha256(trace_jsonl_bytes).hexdigest(),
            "publication-trace-manifest.json": hashlib.sha256(manifest_bytes).hexdigest(),
            "publication-query-vector.json": query_vector_sha256,
        }
    )
    return PublicationTraceBundle(
        manifest=manifest,
        records=records,
        manifest_bytes=manifest_bytes,
        trace_jsonl_bytes=trace_jsonl_bytes,
        query_vector_bytes=query_vector_bytes,
        checksums=checksums,
    )


def _prepare_publication_trace(
    request: _LocalTraceRequest,
    *,
    config: _TraceConfig,
    repository_snapshot: _RepositorySnapshot,
) -> PublicationTraceBundle:
    """Private pytest-only local-source fixture seam with permanent HOLD authority."""

    _require_pytest_fixture_seam()
    return _prepare_verified_publication_trace(
        _VerifiedAcquisitionInput(
            request=request,
            binding=_test_only_fixture_acquisition_binding(request),
        ),
        config=config,
        repository_snapshot=repository_snapshot,
    )


def prepare_publication_trace(request: PublicationTraceRequest) -> PublicationTraceBundle:
    """Prepare one trace from a repository-verified closed acquisition transaction."""

    repository_root = Path(__file__).resolve().parents[2]
    if type(request) is not PublicationTraceRequest:
        raise TypeError("request must be an exact PublicationTraceRequest")
    _require_path_outside_repository(
        request.acquisition_bundle_dir,
        repository_root,
        field="acquisition bundle directory",
    )
    acquisition = _verified_acquisition_input(
        request,
        repository_root=repository_root,
        acquisition_repository_snapshot=_current_acquisition_repository_snapshot(repository_root),
    )
    for source in acquisition.request.sources:
        _require_path_outside_repository(
            source.path,
            repository_root,
            field=f"raw source object {source.role}",
        )
        if type(source.license_terms_objects) is not tuple or any(
            type(terms) is not LicenseTermsObject for terms in source.license_terms_objects
        ):
            raise TypeError(
                "request source license_terms_objects must contain exact LicenseTermsObject values"
            )
        for terms in source.license_terms_objects:
            _require_path_outside_repository(
                terms.path,
                repository_root,
                field=f"license terms object {terms.source_url}",
            )
    repository_snapshot = _verify_clean_repository_snapshot(repository_root)
    return _prepare_verified_publication_trace(
        acquisition,
        config=_PRODUCTION_CONFIG,
        repository_snapshot=repository_snapshot,
    )


def _test_only_prepare_publication_trace_from_bundle(
    request: PublicationTraceRequest,
    *,
    config: _TraceConfig,
    repository_snapshot: _RepositorySnapshot,
    repository_root: Path,
) -> PublicationTraceBundle:
    """Exercise the real closed-bundle path with conspicuously non-authoritative fixtures."""

    _require_pytest_fixture_seam()
    from dynamic_cssc.publication_acquisition import (
        _test_only_repository_snapshot as acquisition_snapshot,
    )

    acquisition = _verified_acquisition_input(
        request,
        repository_root=repository_root,
        acquisition_repository_snapshot=acquisition_snapshot(),
    )
    return _prepare_verified_publication_trace(
        acquisition,
        config=config,
        repository_snapshot=repository_snapshot,
    )


def read_canonical_raw_events(
    dataset_id: str,
    sources: Sequence[LocalSourceObject],
) -> CanonicalRawEventBatch:
    """Read verified local source objects through one canonical raw-event seam."""

    return _read_canonical_raw_events(dataset_id, sources, config=_PRODUCTION_CONFIG)


def source_partition(dataset_release: str, canonical_source_id: str) -> int:
    """Assign a canonical source identity to one of the five frozen partitions."""

    if not isinstance(dataset_release, str) or not dataset_release:
        raise ValueError("dataset_release must be a nonempty string")
    if not isinstance(canonical_source_id, str) or not canonical_source_id:
        raise ValueError("canonical_source_id must be a nonempty string")
    digest = hashlib.sha256((dataset_release + canonical_source_id).encode("utf-8")).digest()
    return int.from_bytes(digest, "big") % 5


def frozen_dataset_release(dataset_id: str) -> str:
    """Return the repository-owned release identity for a primary dataset."""

    try:
        return _DATASET_RELEASES[dataset_id]
    except (KeyError, TypeError) as error:
        raise ValueError(f"unsupported primary dataset: {dataset_id!r}") from error
