"""Closed, exact scheduling for Phase-E publication traces.

The module deliberately exposes a small interface. It validates one trace bundle,
compiles query arrivals without materialising QUERY events, and streams exact publication
windows while keeping accepted-event groups atomic. Bundle validation proves local format,
digest, and transform consistency; source acquisition and Git authority remain separate,
zero-argument evidence-chain responsibilities.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections import Counter, deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from fractions import Fraction
from pathlib import Path
from typing import Any

from dynamic_cssc.evidence_compatibility import (
    BEHAVIOR_INVENTORY_SCHEMA,
    EvidenceRole,
    repository_behavior_paths,
)
from dynamic_cssc.publication_traces import (
    _LICENSE_TERMS_MEDIA_TYPES,
    _LICENSE_TERMS_SECTION_ANCHORS,
    _LICENSE_TERMS_URLS,
    _NYC_TRIP_URLS,
    _NYC_ZONE_URL,
    _PUBLICATION_BEHAVIOR_PATHS,
    _SIMPLEWIKI_URL,
    _SOURCE_MEDIA_TYPES,
    _STACK_OVERFLOW_URLS,
    ACQUISITION_RECEIPT_SCHEMA,
    ACQUISITION_TRACE_BINDING_SCHEMA,
    CANONICAL_RAW_EVENT_SCHEMA,
    PARSER_RUNTIME_SCHEMA,
    PUBLICATION_MAPPING_SCHEMA,
    PUBLICATION_QUERY_VECTOR_SCHEMA,
    PUBLICATION_TRACE_MANIFEST_SCHEMA,
    PUBLICATION_TRANSITION_SCHEMA,
    REPOSITORY_PROVENANCE_SCHEMA,
    PublicationTransition,
    TransitionEventProvenance,
    _canonical_json_bytes,
    _publication_query_vector_payload,
    frozen_dataset_release,
)

ACCEPTED_EVENT_SCHEDULE_SCHEMA = "dynamic-cssc-accepted-event-schedule-v2"

_BUNDLE_FILENAMES = (
    "publication-trace-manifest.json",
    "publication-trace.jsonl",
    "publication-query-vector.json",
    "checksums.sha256",
)
_CHECKSUM_TARGETS = _BUNDLE_FILENAMES[:3]
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}")
_GIT_OBJECT_ID = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
_PRODUCTION_TRACE_TOKEN = object()
_TEST_TRACE_TOKEN = object()
_PRODUCTION_PROGRAM_TOKEN = object()
_TEST_PROGRAM_TOKEN = object()
_PRODUCTION_RHO_VALUES = frozenset(
    {
        Fraction(1, 100),
        Fraction(3, 100),
        Fraction(1, 10),
        Fraction(3, 10),
        Fraction(1),
        Fraction(3),
        Fraction(10),
        Fraction(30),
        Fraction(100),
    }
)
_PRODUCTION_FRESHNESS_VALUES = frozenset({Fraction(1, 10), Fraction(1)})
_FILTER_COUNT_KEYS = frozenset(
    {
        "after-target",
        "other-source-partition",
        "unselected-source",
        "unselected-target",
    }
)
_SOURCE_EVENT_TYPES = {
    "stack-overflow": frozenset({"a2q", "c2a", "c2q"}),
    "simplewiki-2026-07": frozenset({"revision-create"}),
    "nyc-tlc-yellow-2022": frozenset({"yellow-trip"}),
}
_REJECTED_EVENT_COUNT_KEYS = {
    "stack-overflow": frozenset({"malformed-record", "self-loop"}),
    "simplewiki-2026-07": frozenset(
        {
            "invalid-timestamp",
            "malformed-identity-flags",
            "malformed-record",
            "missing-or-invalid-identity",
            "non-main-namespace",
            "non-permanent-contributor",
            "non-revision-create",
            "wrong-wiki-database",
        }
    ),
}
_NYC_TRIP_REJECTED_EVENT_COUNT_KEYS = frozenset(
    {
        "dropoff-before-pickup",
        "invalid-timestamp",
        "invalid-zone",
        "nonexistent-local-time",
        "pickup-outside-source-month",
    }
)

_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "protocol_version",
        "artifact_policy",
        "dataset_id",
        "dataset_release",
        "semantics",
        "source_partition",
        "repository_provenance",
        "normalization_contract",
        "ordering",
        "logical_clock",
        "frozen_contract",
        "acquisition_binding",
        "acquisition_receipts",
        "schema_valid_raw_events",
        "mapping",
        "filter_counts",
        "accepted_raw_event_sha256",
        "source_event_type_counts",
        "operation_counts",
        "trace",
        "realized_bounds",
        "query_vector",
        "trace_jsonl_sha256",
        "eligibility",
    }
)
_REPOSITORY_PROVENANCE_KEYS = frozenset(
    {
        "schema_version",
        "source_git_sha",
        "behavior_source_blob_sha256",
        "verification_mode",
        "repository_provenance_sha256",
    }
)
_MAPPING_KEYS = frozenset(
    {
        "schema_version",
        "dataset_id",
        "dataset_release",
        "source_partition",
        "canonical_id_serialization",
        "mapping_prefix_events",
        "row_ids",
        "column_ids",
        "observed_column_count",
        "reserved_empty_column_count",
        "mapping_sha256",
    }
)
_FROZEN_CONTRACT_KEYS = frozenset(
    {
        "rows",
        "cols",
        "mapping_prefix_numerator",
        "mapping_prefix_denominator",
        "mapping_tie_break",
        "source_partition_rule",
        "reserved_column_padding_max_fraction",
        "coefficient_cap",
        "event_window_size",
        "t2_transition_order",
        "t2_expiry_event_provenance",
        "target_accepted_events",
        "minimum_logical_changes",
        "microbatch_cap",
        "microbatch_cap_unit",
        "atomic_transition_group_policy",
        "maximum_atomic_group_size",
        "maximum_transitions_per_microbatch_window",
        "minimum_complete_window_lower_bound",
        "complete_publication_window_count_rule",
        "query_arrival_schedule",
        "query_vector_generation",
        "maximum_row_nonzeros",
        "evaluation_window_split",
    }
)
_QUERY_SCHEDULE_KEYS = frozenset(
    {
        "schema_version",
        "rho_denominator_kind",
        "accepted_event_ordinal_origin",
        "cumulative_query_rule",
        "grouping_key",
        "within_group_order",
        "query_placement",
        "logical_tick_policy",
        "scheduled_event_order",
        "clipped_noop_policy",
    }
)
_QUERY_VECTOR_GENERATION_KEYS = frozenset(
    {
        "schema_version",
        "seed",
        "length",
        "coefficient_bound",
        "generation",
        "forced_boundary_entries",
        "reuse_scope",
        "evaluation_query_plaintext_public",
        "query_confidentiality_evidence_allowed",
        "security_randomness_claim_allowed",
        "query_distribution_claim_allowed",
    }
)
_TRACE_KEYS = frozenset(
    {
        "accepted_raw_events",
        "clipped_noops",
        "complete_publication_window_lower_bound",
        "logical_changes",
        "target_reached",
        "transition_records",
    }
)
_QUERY_VECTOR_BINDING_KEYS = frozenset(
    {"schema_version", "filename", "length", "query_vector_sha256"}
)
_QUERY_VECTOR_KEYS = frozenset(
    {
        "schema_version",
        "dataset_id",
        "dataset_release",
        "semantics",
        "source_partition",
        "mapping_sha256",
        "length",
        "seed",
        "coefficient_bound",
        "generation",
        "reuse_scope",
        "values",
    }
)
_ACQUISITION_BINDING_KEYS = frozenset(
    {
        "schema_version",
        "dataset_id",
        "dataset_release",
        "acquisition_transaction_schema_version",
        "acquisition_transaction_sha256",
        "source_set_schema_version",
        "source_set_sha256",
        "repository_provenance",
        "verification",
        "authority",
    }
)
_ACQUISITION_REPOSITORY_PROVENANCE_KEYS = frozenset(
    {"source_git_sha", "verification_mode", "behavior_inventory"}
)
_ACQUISITION_BEHAVIOR_INVENTORY_KEYS = frozenset(
    {
        "behavior_set_schema_version",
        "behavior_set_sha256",
        "entries",
        "role",
        "schema_version",
        "source_git_sha",
    }
)
_ACQUISITION_VERIFICATION_KEYS = frozenset(
    {
        "bundle_member_set_exact",
        "bundle_members_rehashed_no_follow",
        "embedded_central_inventory_verified",
        "network_fetch_recorded",
        "source_and_terms_objects_rehashed_no_follow",
        "transaction_chain_verified",
    }
)
_ACQUISITION_AUTHORITY_KEYS = frozenset(
    {
        "state",
        "formal_authority_granted",
        "acquisition_network_authority_verified",
        "post_run_anchor_verified",
        "evidence_compatibility_verified",
        "claims_authorized",
    }
)
_ACQUISITION_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "dataset_id",
        "dataset_release",
        "source_git_sha",
        "behavior_source_blob_sha256",
        "repository_provenance_sha256",
        "role",
        "source_url",
        "final_url",
        "http_status",
        "media_type",
        "retrieval_utc",
        "byte_count",
        "http_etag",
        "http_last_modified",
        "local_sha256",
        "publisher_sha256",
        "license_terms_set_sha256",
        "license_terms_objects",
        "attribution_text",
        "redistribution_policy",
        "rejected_event_counts",
    }
)
_LICENSE_TERMS_OBJECT_KEYS = frozenset(
    {
        "source_url",
        "final_url",
        "http_status",
        "media_type",
        "retrieval_utc",
        "http_etag",
        "http_last_modified",
        "section_anchor",
        "byte_count",
        "sha256",
    }
)
_PRODUCTION_PARSER_IDENTITY_KEYS = frozenset(
    {
        "schema_version",
        "container_image_digest",
        "implementation_name",
        "python_version",
        "pyarrow_version",
        "platform_name",
        "machine",
        "platform_tag",
        "timezone_key",
        "timezone_tzif_sha256",
    }
)
_TRANSITION_KEYS = frozenset(
    {
        "schema_version",
        "dataset_id",
        "dataset_release",
        "semantics",
        "source_partition",
        "repository_provenance_sha256",
        "accepted_event_ordinal",
        "transition_ordinal",
        "transition_cause",
        "trigger_event",
        "subject_event",
        "logical_time_numerator",
        "logical_time_denominator",
        "row_index",
        "column_index",
        "operation",
        "before",
        "after",
    }
)
_EVENT_PROVENANCE_KEYS = frozenset(
    {
        "canonical_raw_event_ordinal",
        "source_timestamp_utc",
        "source_file_ordinal",
        "within_file_ordinal",
        "source_event_type",
    }
)
_NORMALIZATION_CONTRACTS: dict[str, dict[str, object]] = {
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
        "timezone_tzif_sha256": (
            "e9ed07d7bee0c76a9d442d091ef1f01668fee7c4f26014c0a868b19fe6c18a95"
        ),
        "directed": True,
        "time_bin": "local-15-minute-bin-of-week",
        "valid_zone_source": "official-taxi-zone-lookup",
    },
}


@dataclass(frozen=True, slots=True)
class _TraceGroup:
    accepted_ordinal: int
    logical_time: Fraction
    transitions: tuple[PublicationTransition, ...]


@dataclass(frozen=True, slots=True)
class ValidatedPublicationTrace:
    """Immutable result of validating and rehashing one closed trace bundle."""

    trace_dir: Path
    dataset_id: str
    dataset_release: str
    semantics: str
    source_partition: int
    repository_provenance_sha256: str
    mapping_sha256: str
    accepted_group_count: int
    transition_count: int
    clock_denominator: int
    microbatch_max_updates: int
    coefficient_cap: int
    rows: int
    cols: int
    query_vector: tuple[int, ...]
    manifest_sha256: str
    trace_jsonl_sha256: str
    query_vector_sha256: str
    eligible: bool
    _groups: tuple[_TraceGroup, ...] = field(repr=False)
    _validation_token: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class AcceptedGroupPhaseRange:
    name: str
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class ScheduledSet:
    transition_ordinal: int
    transition_cause: str
    row: int
    col: int
    before: int
    after: int

    @property
    def kind(self) -> str:
        return "set"


@dataclass(frozen=True, slots=True)
class ScheduledQueryRun:
    first_query_ordinal: int
    count: int

    @property
    def kind(self) -> str:
        return "query-run"


@dataclass(frozen=True, slots=True)
class ScheduledAcceptedGroup:
    accepted_ordinal: int
    phase: str
    logical_time: Fraction
    sets: tuple[ScheduledSet, ...]
    query_run: ScheduledQueryRun
    phase_close_after: str | None

    @property
    def event_kinds(self) -> tuple[str, ...]:
        kinds = (*("set" for _ in self.sets), "tick", "query-run")
        if self.phase_close_after is not None:
            return (*kinds, "phase-boundary")
        return kinds


@dataclass(frozen=True, slots=True)
class AcceptedGroupProgram:
    schema_version: str
    trace: ValidatedPublicationTrace
    rho: Fraction
    phase_ranges: tuple[AcceptedGroupPhaseRange, ...]
    accepted_group_count: int
    total_set_count: int
    total_query_count: int
    scheduled_event_count: int
    canonical_schedule_sha256: str
    _groups: tuple[ScheduledAcceptedGroup, ...] = field(repr=False)
    _program_token: object = field(repr=False, compare=False)

    def __iter__(self) -> Iterator[ScheduledAcceptedGroup]:
        return iter(self._groups)

    def iter_canonical_bytes(self) -> Iterator[bytes]:
        yield _canonical_json_bytes(_program_header_payload(self))
        for group in self._groups:
            yield _canonical_json_bytes(_scheduled_group_payload(group))


@dataclass(frozen=True, slots=True)
class ScheduledNetUpdate:
    row: int
    col: int
    before: int
    after: int


@dataclass(frozen=True, slots=True)
class ExactPublicationWindow:
    index: int
    phase: str
    accepted_group_start: int
    accepted_group_end: int
    start_time: Fraction
    end_time: Fraction
    set_count: int
    updates: tuple[ScheduledNetUpdate, ...]
    query_count: int
    reason: str


_ISSUED_PRODUCTION_TRACES: dict[int, ValidatedPublicationTrace] = {}
_ISSUED_TEST_TRACES: dict[int, ValidatedPublicationTrace] = {}
_ISSUED_PRODUCTION_PROGRAMS: dict[int, AcceptedGroupProgram] = {}
_ISSUED_TEST_PROGRAMS: dict[int, AcceptedGroupProgram] = {}


def _closed_keys(payload: dict[str, object], expected: frozenset[str], field: str) -> None:
    actual = set(payload)
    if actual != expected:
        raise ValueError(
            f"{field} keys must be exactly {sorted(expected)}; "
            f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
        )


def _object(value: object, field: str) -> dict[str, object]:
    if type(value) is not dict:
        raise ValueError(f"{field} must be a JSON object")
    return value


def _list(value: object, field: str) -> list[object]:
    if type(value) is not list:
        raise ValueError(f"{field} must be a JSON array")
    return value


def _string(value: object, field: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{field} must be a nonempty string")
    return value


def _integer(value: object, field: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{field} must be an exact integer >= {minimum}")
    return value


def _boolean(value: object, field: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{field} must be a boolean")
    return value


def _sha256(value: object, field: str) -> str:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise ValueError(f"duplicate JSON object key is forbidden: {key}")
        payload[key] = value
    return payload


def _reject_float(token: str) -> Any:
    raise ValueError(f"JSON floating-point values are forbidden: {token}")


def _decode_canonical_json(raw: bytes, field: str) -> object:
    try:
        text = raw.decode("utf-8")
        payload = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_reject_float,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON value is forbidden: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{field} must be valid canonical UTF-8 JSON") from error
    if _canonical_json_bytes(payload) != raw:
        raise ValueError(f"{field} must use canonical JSON serialization")
    return payload


def _read_regular_file(path: Path, field: str) -> bytes:
    if path.is_symlink():
        raise ValueError(f"{field} must not be a symbolic link")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"{field} must name an existing regular file") from error
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError(f"{field} must name an existing regular file")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _validate_nonnegative_count_map(
    value: object,
    field: str,
    *,
    allowed_keys: frozenset[str] | None = None,
    sparse: bool = False,
) -> dict[str, int]:
    payload = _object(value, field)
    if any(type(key) is not str or not key for key in payload):
        raise ValueError(f"{field} keys must be nonempty strings")
    if allowed_keys is not None and not set(payload) <= allowed_keys:
        unexpected = sorted(set(payload) - allowed_keys)
        raise ValueError(f"{field} contains non-frozen count keys: {unexpected}")
    counts = {key: _integer(count, f"{field}.{key}") for key, count in payload.items()}
    if sparse and any(count == 0 for count in counts.values()):
        raise ValueError(f"{field} must omit zero-valued sparse count categories")
    return counts


def _nullable_string(value: object, field: str) -> str | None:
    if value is None:
        return None
    return _string(value, field)


def _expected_source_url(dataset_id: str, role: str) -> str:
    if dataset_id == "stack-overflow":
        return _STACK_OVERFLOW_URLS[role]
    if dataset_id == "simplewiki-2026-07" and role == "history":
        return _SIMPLEWIKI_URL
    if dataset_id == "nyc-tlc-yellow-2022":
        return _NYC_ZONE_URL if role == "zone-lookup" else _NYC_TRIP_URLS[role]
    raise ValueError("acquisition receipt role is not frozen for its dataset")


def _validate_acquisition(manifest: dict[str, object]) -> None:
    dataset_id = str(manifest["dataset_id"])
    binding = _object(manifest["acquisition_binding"], "acquisition_binding")
    _closed_keys(binding, _ACQUISITION_BINDING_KEYS, "acquisition_binding")
    if binding["schema_version"] != ACQUISITION_TRACE_BINDING_SCHEMA:
        raise ValueError("acquisition_binding schema is not frozen")
    if (
        binding["dataset_id"] != dataset_id
        or binding["dataset_release"] != manifest["dataset_release"]
    ):
        raise ValueError("acquisition_binding dataset identity does not match the trace")
    if (
        binding["acquisition_transaction_schema_version"]
        != "dynamic-cssc-acquisition-transaction-v3"
    ):
        raise ValueError("acquisition transaction schema is not frozen")
    if binding["source_set_schema_version"] != "dynamic-cssc-local-source-set-v5":
        raise ValueError("acquisition source-set schema is not frozen")
    _sha256(
        binding["acquisition_transaction_sha256"],
        "acquisition_transaction_sha256",
    )
    _sha256(binding["source_set_sha256"], "source_set_sha256")

    acquisition_provenance = _object(
        binding["repository_provenance"],
        "acquisition_binding.repository_provenance",
    )
    _closed_keys(
        acquisition_provenance,
        _ACQUISITION_REPOSITORY_PROVENANCE_KEYS,
        "acquisition_binding.repository_provenance",
    )
    acquisition_source_sha = _string(
        acquisition_provenance["source_git_sha"],
        "acquisition experiment source_git_sha",
    )
    if (
        len(acquisition_source_sha) != 40
        or _GIT_OBJECT_ID.fullmatch(acquisition_source_sha) is None
    ):
        raise ValueError("acquisition experiment source_git_sha must be an exact Git commit ID")
    acquisition_mode = acquisition_provenance["verification_mode"]
    if acquisition_mode not in {
        "hardened-acquisition-role-git-object-worktree-v1",
        "test-only-fixed-repository-snapshot-v1",
    }:
        raise ValueError("acquisition repository verification_mode is not recognized")
    inventory = _object(
        acquisition_provenance["behavior_inventory"],
        "acquisition behavior_inventory",
    )
    _closed_keys(
        inventory,
        _ACQUISITION_BEHAVIOR_INVENTORY_KEYS,
        "acquisition behavior_inventory",
    )
    if (
        inventory["schema_version"] != BEHAVIOR_INVENTORY_SCHEMA
        or inventory["behavior_set_schema_version"] != "dynamic-cssc-acquisition-behavior-set-v2"
        or inventory["role"] != EvidenceRole.ACQUISITION.value
        or inventory["source_git_sha"] != acquisition_source_sha
    ):
        raise ValueError("acquisition behavior_inventory identity is not exact")
    behavior_set_sha256 = _sha256(
        inventory["behavior_set_sha256"],
        "acquisition behavior_set_sha256",
    )
    entries = _list(inventory["entries"], "acquisition behavior_inventory.entries")
    expected_paths = repository_behavior_paths(EvidenceRole.ACQUISITION)
    if (
        tuple(
            _object(entry, f"acquisition behavior_inventory.entries[{index}]").get("path")
            for index, entry in enumerate(entries)
        )
        != expected_paths
    ):
        raise ValueError("acquisition behavior_inventory does not bind the central path set")
    for index, raw_entry in enumerate(entries):
        field = f"acquisition behavior_inventory.entries[{index}]"
        entry = _object(raw_entry, field)
        _closed_keys(
            entry,
            frozenset({"mode", "object_id", "object_type", "path"}),
            field,
        )
        object_id = _string(entry["object_id"], f"{field}.object_id")
        if (
            entry["mode"] not in {"100644", "100755"}
            or entry["object_type"] != "blob"
            or len(object_id) != 40
            or _GIT_OBJECT_ID.fullmatch(object_id) is None
        ):
            raise ValueError(f"{field} is not an exact Git blob entry")
    behavior_core = {
        "behavior_set_schema_version": inventory["behavior_set_schema_version"],
        "entries": entries,
        "role": inventory["role"],
    }
    if (
        acquisition_mode == "hardened-acquisition-role-git-object-worktree-v1"
        and behavior_set_sha256 != hashlib.sha256(_canonical_json_bytes(behavior_core)).hexdigest()
    ):
        raise ValueError("hardened acquisition behavior_set_sha256 is not self-consistent")

    verification = _object(binding["verification"], "acquisition_binding.verification")
    _closed_keys(
        verification,
        _ACQUISITION_VERIFICATION_KEYS,
        "acquisition_binding.verification",
    )
    hardened_verification = {key: True for key in _ACQUISITION_VERIFICATION_KEYS}
    fixture_bundle_verification = {
        **hardened_verification,
        "embedded_central_inventory_verified": False,
        "network_fetch_recorded": False,
    }
    local_fixture_verification = {
        key: key == "source_and_terms_objects_rehashed_no_follow"
        for key in _ACQUISITION_VERIFICATION_KEYS
    }
    if acquisition_mode == "hardened-acquisition-role-git-object-worktree-v1":
        expected_verification = hardened_verification
        expected_authority_state = "HOLD-no-repository-post-run-anchor"
    elif verification == fixture_bundle_verification:
        expected_verification = fixture_bundle_verification
        expected_authority_state = "HOLD-test-only-fixture-no-post-run-anchor"
    else:
        expected_verification = local_fixture_verification
        expected_authority_state = "HOLD-test-only-local-source-fixture"
    if verification != expected_verification:
        raise ValueError("acquisition_binding verification facts are not exact")

    authority = _object(binding["authority"], "acquisition_binding.authority")
    _closed_keys(authority, _ACQUISITION_AUTHORITY_KEYS, "acquisition_binding.authority")
    expected_authority = {
        "state": expected_authority_state,
        "formal_authority_granted": False,
        "acquisition_network_authority_verified": False,
        "post_run_anchor_verified": False,
        "evidence_compatibility_verified": False,
        "claims_authorized": False,
    }
    if authority != expected_authority:
        raise ValueError("acquisition_binding authority must remain exact HOLD/false")

    receipts = _list(manifest["acquisition_receipts"], "acquisition_receipts")
    if dataset_id == "stack-overflow":
        expected_roles = ("a2q", "c2q", "c2a")
    elif dataset_id == "simplewiki-2026-07":
        expected_roles = ("history",)
    else:
        expected_roles = (*sorted(_NYC_TRIP_URLS), "zone-lookup")
    if (
        tuple(
            _object(receipt, f"acquisition_receipts[{index}]").get("role")
            for index, receipt in enumerate(receipts)
        )
        != expected_roles
    ):
        raise ValueError("acquisition receipts must use the exact frozen role order")

    provenance = _object(manifest["repository_provenance"], "repository_provenance")
    expected_terms_urls = _LICENSE_TERMS_URLS[dataset_id]
    for index, value in enumerate(receipts):
        field = f"acquisition_receipts[{index}]"
        receipt = _object(value, field)
        _closed_keys(receipt, _ACQUISITION_RECEIPT_KEYS, field)
        if receipt["schema_version"] != ACQUISITION_RECEIPT_SCHEMA:
            raise ValueError(f"{field}.schema_version is not frozen")
        for name in ("dataset_id", "dataset_release"):
            if receipt[name] != manifest[name]:
                raise ValueError(f"{field}.{name} does not match the manifest")
        for name in (
            "source_git_sha",
            "behavior_source_blob_sha256",
            "repository_provenance_sha256",
        ):
            if receipt[name] != provenance[name]:
                raise ValueError(f"{field}.{name} does not match repository provenance")
        role = _string(receipt["role"], f"{field}.role")
        source_url = _expected_source_url(dataset_id, role)
        if receipt["source_url"] != source_url or receipt["final_url"] != source_url:
            raise ValueError(f"{field} source/final URL is not frozen")
        if receipt["http_status"] != 200:
            raise ValueError(f"{field}.http_status must be the exact integer 200")
        if receipt["media_type"] not in _SOURCE_MEDIA_TYPES[source_url]:
            raise ValueError(f"{field}.media_type is not frozen for the source")
        retrieval_utc = _string(receipt["retrieval_utc"], f"{field}.retrieval_utc")
        if not retrieval_utc.endswith("Z"):
            raise ValueError(f"{field}.retrieval_utc must be one UTC instant")
        _integer(receipt["byte_count"], f"{field}.byte_count")
        _nullable_string(receipt["http_etag"], f"{field}.http_etag")
        _nullable_string(receipt["http_last_modified"], f"{field}.http_last_modified")
        _sha256(receipt["local_sha256"], f"{field}.local_sha256")
        if receipt["publisher_sha256"] is not None:
            _sha256(receipt["publisher_sha256"], f"{field}.publisher_sha256")
        terms = _list(receipt["license_terms_objects"], f"{field}.license_terms_objects")
        term_urls: list[str] = []
        for term_index, term_value in enumerate(terms):
            term_field = f"{field}.license_terms_objects[{term_index}]"
            term = _object(term_value, term_field)
            _closed_keys(term, _LICENSE_TERMS_OBJECT_KEYS, term_field)
            term_url = _string(term["source_url"], f"{term_field}.source_url")
            term_urls.append(term_url)
            if term["final_url"] != term_url or term["http_status"] != 200:
                raise ValueError(f"{term_field} final URL/status is not exact")
            media_type = _string(term["media_type"], f"{term_field}.media_type")
            if media_type not in _LICENSE_TERMS_MEDIA_TYPES[term_url]:
                raise ValueError(f"{term_field}.media_type is not frozen")
            term_retrieval_utc = _string(term["retrieval_utc"], f"{term_field}.retrieval_utc")
            if not term_retrieval_utc.endswith("Z"):
                raise ValueError(f"{term_field}.retrieval_utc must be one UTC instant")
            _nullable_string(term["http_etag"], f"{term_field}.http_etag")
            _nullable_string(term["http_last_modified"], f"{term_field}.http_last_modified")
            if term["section_anchor"] != _LICENSE_TERMS_SECTION_ANCHORS[term_url]:
                raise ValueError(f"{term_field}.section_anchor is not frozen")
            _integer(term["byte_count"], f"{term_field}.byte_count")
            _sha256(term["sha256"], f"{term_field}.sha256")
        if tuple(term_urls) != tuple(sorted(expected_terms_urls)):
            raise ValueError(f"{field} license terms set is not exact")
        terms_digest = _sha256(
            receipt["license_terms_set_sha256"], f"{field}.license_terms_set_sha256"
        )
        if terms_digest != hashlib.sha256(_canonical_json_bytes(terms)).hexdigest():
            raise ValueError(f"{field}.license_terms_set_sha256 does not bind its objects")
        _string(receipt["attribution_text"], f"{field}.attribution_text")
        if receipt["redistribution_policy"] != "derived-trace-and-download-by-source-only":
            raise ValueError(f"{field}.redistribution_policy is not frozen")
        if dataset_id == "nyc-tlc-yellow-2022":
            rejected_keys = (
                frozenset({"invalid-zone-record"})
                if role == "zone-lookup"
                else _NYC_TRIP_REJECTED_EVENT_COUNT_KEYS
            )
        else:
            rejected_keys = _REJECTED_EVENT_COUNT_KEYS[dataset_id]
        _validate_nonnegative_count_map(
            receipt["rejected_event_counts"],
            f"{field}.rejected_event_counts",
            allowed_keys=rejected_keys,
            sparse=True,
        )


def _validate_nyc_parser_identity(value: object) -> bool:
    """Return whether the identity has production form, without verifying its host."""

    identity = _object(value, "normalization_contract.parser_runtime_identity")
    if set(identity) == {"schema_version", "verification_mode"}:
        if identity != {
            "schema_version": PARSER_RUNTIME_SCHEMA,
            "verification_mode": "test-only-csv-fixture-no-publication-authority",
        }:
            raise ValueError("test-only NYC parser identity is not exact")
        return False
    _closed_keys(
        identity,
        _PRODUCTION_PARSER_IDENTITY_KEYS,
        "normalization_contract.parser_runtime_identity",
    )
    if (
        identity["schema_version"] != PARSER_RUNTIME_SCHEMA
        or identity["container_image_digest"] is not None
        or identity["implementation_name"] != "cpython"
        or identity["python_version"] != "3.12.13"
        or identity["pyarrow_version"] != "25.0.1"
        or identity["timezone_key"] != "America/New_York"
        or identity["timezone_tzif_sha256"]
        != "e9ed07d7bee0c76a9d442d091ef1f01668fee7c4f26014c0a868b19fe6c18a95"
    ):
        raise ValueError("production NYC parser identity is not exact")
    platform_name = identity["platform_name"]
    machine = identity["machine"]
    if (platform_name, machine) not in {
        ("darwin", "arm64"),
        ("darwin", "x86_64"),
        ("linux", "aarch64"),
        ("linux", "x86_64"),
    }:
        raise ValueError("NYC parser platform/machine pair is not admitted")
    _string(identity["platform_tag"], "parser_runtime_identity.platform_tag")
    return True


def _parse_checksums(raw: bytes) -> dict[str, str]:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("checksums.sha256 must be ASCII") from error
    lines = text.splitlines(keepends=True)
    if len(lines) != len(_CHECKSUM_TARGETS):
        raise ValueError("checksums.sha256 must bind exactly the three trace artifacts")
    checksums: dict[str, str] = {}
    for line, expected_name in zip(lines, _CHECKSUM_TARGETS, strict=True):
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\n]+)\n", line)
        if match is None or match.group(2) != expected_name:
            raise ValueError("checksums.sha256 must use the frozen names and canonical order")
        checksums[expected_name] = match.group(1)
    return checksums


def _validate_manifest(payload: object) -> dict[str, object]:
    manifest = _object(payload, "trace manifest")
    _closed_keys(manifest, _MANIFEST_KEYS, "trace manifest")
    if manifest["schema_version"] != PUBLICATION_TRACE_MANIFEST_SCHEMA:
        raise ValueError(f"trace manifest schema must be {PUBLICATION_TRACE_MANIFEST_SCHEMA}")
    if manifest["protocol_version"] != "2.1b":
        raise ValueError("trace manifest protocol_version must be 2.1b")
    if manifest["artifact_policy"] != "derived-trace-and-download-by-source-only":
        raise ValueError("trace manifest artifact_policy is not frozen")
    dataset_id = _string(manifest["dataset_id"], "trace manifest.dataset_id")
    if manifest["dataset_release"] != frozen_dataset_release(dataset_id):
        raise ValueError("trace manifest dataset_release is not repository-frozen")
    if manifest["semantics"] not in {"T1", "T2"}:
        raise ValueError("trace manifest semantics must be T1 or T2")
    source_partition = _integer(manifest["source_partition"], "trace manifest.source_partition")
    if source_partition >= 5:
        raise ValueError("trace manifest source_partition must be in [0, 5)")

    normalization = _object(manifest["normalization_contract"], "normalization_contract")
    expected_normalization = _NORMALIZATION_CONTRACTS[dataset_id]
    expected_normalization_keys = set(expected_normalization)
    if dataset_id == "nyc-tlc-yellow-2022":
        expected_normalization_keys.add("parser_runtime_identity")
    _closed_keys(
        normalization,
        frozenset(expected_normalization_keys),
        "normalization_contract",
    )
    if any(normalization[key] != value for key, value in expected_normalization.items()):
        raise ValueError("normalization_contract does not match the frozen dataset adapter")
    if dataset_id == "nyc-tlc-yellow-2022":
        _validate_nyc_parser_identity(normalization["parser_runtime_identity"])

    provenance = _object(manifest["repository_provenance"], "repository_provenance")
    _closed_keys(provenance, _REPOSITORY_PROVENANCE_KEYS, "repository_provenance")
    if provenance["schema_version"] != REPOSITORY_PROVENANCE_SCHEMA:
        raise ValueError("repository provenance schema is not frozen")
    source_git_sha = _string(provenance["source_git_sha"], "source_git_sha")
    if _GIT_OBJECT_ID.fullmatch(source_git_sha) is None:
        raise ValueError("source_git_sha must be a canonical Git object ID")
    behavior_digests = _object(
        provenance["behavior_source_blob_sha256"], "behavior_source_blob_sha256"
    )
    if not behavior_digests:
        raise ValueError("behavior_source_blob_sha256 must not be empty")
    for path, digest in behavior_digests.items():
        _string(path, "behavior source path")
        _sha256(digest, f"behavior_source_blob_sha256[{path!r}]")
    if provenance["verification_mode"] not in {
        "hardened-trace-role-git-object-worktree-v1",
        "test-only-fixed-repository-snapshot-v1",
    }:
        raise ValueError("repository provenance verification_mode is not recognized")
    provenance_digest = _sha256(
        provenance["repository_provenance_sha256"], "repository_provenance_sha256"
    )
    provenance_core = {
        key: value for key, value in provenance.items() if key != "repository_provenance_sha256"
    }
    if provenance_digest != hashlib.sha256(_canonical_json_bytes(provenance_core)).hexdigest():
        raise ValueError("repository_provenance_sha256 does not bind its payload")
    _validate_acquisition(manifest)

    ordering = _list(manifest["ordering"], "trace manifest.ordering")
    if ordering != ["normalized-utc", "source-file-ordinal", "within-file-ordinal"]:
        raise ValueError("trace manifest ordering is not frozen")
    logical_clock = _object(manifest["logical_clock"], "logical_clock")
    _closed_keys(
        logical_clock,
        frozenset(
            {
                "accepted_events_per_second",
                "first_accepted_event_tick",
                "historical_time_is_provenance_only",
            }
        ),
        "logical_clock",
    )
    accepted_events_per_second = _integer(
        logical_clock["accepted_events_per_second"],
        "accepted_events_per_second",
        minimum=1,
    )
    if accepted_events_per_second != 128:
        raise ValueError("accepted-event logical clock must be exactly 128 Hz")
    if logical_clock["first_accepted_event_tick"] != 0:
        raise ValueError("first accepted-event tick must be zero")
    if logical_clock["historical_time_is_provenance_only"] is not True:
        raise ValueError("historical timestamps must be provenance-only")

    contract = _object(manifest["frozen_contract"], "frozen_contract")
    _closed_keys(contract, _FROZEN_CONTRACT_KEYS, "frozen_contract")
    for name in (
        "rows",
        "cols",
        "mapping_prefix_numerator",
        "mapping_prefix_denominator",
        "coefficient_cap",
        "event_window_size",
        "target_accepted_events",
        "minimum_logical_changes",
        "microbatch_cap",
        "maximum_atomic_group_size",
        "maximum_transitions_per_microbatch_window",
        "minimum_complete_window_lower_bound",
        "maximum_row_nonzeros",
    ):
        _integer(contract[name], f"frozen_contract.{name}", minimum=1)
    if (contract["mapping_prefix_numerator"], contract["mapping_prefix_denominator"]) != (1, 10):
        raise ValueError("mapping prefix must be exactly 1/10")
    if contract["mapping_tie_break"] != "canonical-id-ascending":
        raise ValueError("mapping tie break is not frozen")
    if contract["source_partition_rule"] != (
        "big-endian-SHA256(dataset_release||canonical_source_id)-mod-5"
    ):
        raise ValueError("source partition rule is not frozen")
    if contract["reserved_column_padding_max_fraction"] != "1/10":
        raise ValueError("reserved-column padding cap is not frozen")
    if contract["t2_transition_order"] != "expiry-before-admission":
        raise ValueError("T2 transition order is not frozen")
    if contract["t2_expiry_event_provenance"] != (
        "trigger-event-is-incoming-raw-event;subject-event-is-expired-raw-event"
    ):
        raise ValueError("T2 expiry provenance rule is not frozen")
    if contract["microbatch_cap"] != 64:
        raise ValueError("publication microbatch threshold must be exactly 64 SETs")
    maximum_atomic_group_size = 1 if manifest["semantics"] == "T1" else 2
    if contract["maximum_atomic_group_size"] != maximum_atomic_group_size:
        raise ValueError("maximum_atomic_group_size does not match trace semantics")
    if contract["maximum_transitions_per_microbatch_window"] != 64 + maximum_atomic_group_size - 1:
        raise ValueError("maximum transitions per group-atomic window is inconsistent")
    if contract["microbatch_cap_unit"] != "emitted-logical-set-transitions":
        raise ValueError("microbatch cap unit is not frozen")
    if contract["atomic_transition_group_policy"] != "accepted-event-group-never-split":
        raise ValueError("atomic transition-group policy is not frozen")
    if contract["complete_publication_window_count_rule"] != (
        "floor(emitted_logical_changes/maximum-transitions-per-atomic-window)-"
        "conservative-lower-bound"
    ):
        raise ValueError("complete-window lower-bound rule is not frozen")

    query_schedule = _object(contract["query_arrival_schedule"], "query_arrival_schedule")
    _closed_keys(query_schedule, _QUERY_SCHEDULE_KEYS, "query_arrival_schedule")
    expected_schedule = {
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
    }
    if query_schedule != expected_schedule:
        raise ValueError("query arrival schedule is not the frozen closed contract")

    vector_generation = _object(contract["query_vector_generation"], "query_vector_generation")
    _closed_keys(
        vector_generation,
        _QUERY_VECTOR_GENERATION_KEYS,
        "query_vector_generation",
    )
    if vector_generation["schema_version"] != PUBLICATION_QUERY_VECTOR_SCHEMA:
        raise ValueError("query-vector generation schema is not frozen")
    if vector_generation["length"] != contract["cols"]:
        raise ValueError("query-vector generation length must equal frozen cols")
    if vector_generation["security_randomness_claim_allowed"] is not False:
        raise ValueError("query vector must not claim security randomness")
    if vector_generation["query_distribution_claim_allowed"] is not False:
        raise ValueError("query vector must not claim a query distribution")
    if vector_generation["evaluation_query_plaintext_public"] is not True:
        raise ValueError("evaluation query plaintext must be explicitly public")
    if vector_generation["query_confidentiality_evidence_allowed"] is not False:
        raise ValueError("query vector must not claim query-confidentiality evidence")
    forced_boundary_entries = {"0": 1}
    if contract["cols"] > 1:
        forced_boundary_entries[str(contract["cols"] - 1)] = -1
    expected_vector_generation = {
        "schema_version": PUBLICATION_QUERY_VECTOR_SCHEMA,
        "seed": 2_026_082_302,
        "length": contract["cols"],
        "coefficient_bound": 1,
        "generation": "shake256-per-coordinate-rejection-sampling",
        "forced_boundary_entries": forced_boundary_entries,
        "reuse_scope": "one-vector-per-paired-analysis-unit-all-query-arrivals",
        "evaluation_query_plaintext_public": True,
        "query_confidentiality_evidence_allowed": False,
        "security_randomness_claim_allowed": False,
        "query_distribution_claim_allowed": False,
    }
    if vector_generation != expected_vector_generation:
        raise ValueError("query-vector generation contract is not exact")
    split = _object(contract["evaluation_window_split"], "evaluation_window_split")
    _closed_keys(
        split,
        frozenset(
            {
                "warmup_numerator",
                "tuning_numerator",
                "held_out_numerator",
                "denominator",
                "state_reset_between_splits",
            }
        ),
        "evaluation_window_split",
    )
    if split != {
        "warmup_numerator": 1,
        "tuning_numerator": 3,
        "held_out_numerator": 6,
        "denominator": 10,
        "state_reset_between_splits": False,
    }:
        raise ValueError("evaluation split must be the exact common 10/30/60 contract")

    mapping = _object(manifest["mapping"], "mapping")
    _closed_keys(mapping, _MAPPING_KEYS, "mapping")
    if mapping["schema_version"] != PUBLICATION_MAPPING_SCHEMA:
        raise ValueError("mapping schema is not frozen")
    for name in ("dataset_id", "dataset_release", "source_partition"):
        if mapping[name] != manifest[name]:
            raise ValueError(f"mapping.{name} does not match trace manifest")
    if mapping["canonical_id_serialization"] != "utf-8-ascii-prefixed-zero-padded-v1":
        raise ValueError("mapping canonical ID serialization is not frozen")
    _integer(mapping["mapping_prefix_events"], "mapping.mapping_prefix_events")
    row_ids = _list(mapping["row_ids"], "mapping.row_ids")
    column_ids = _list(mapping["column_ids"], "mapping.column_ids")
    if not row_ids or len(row_ids) > contract["rows"]:
        raise ValueError("mapping row_ids cardinality is invalid")
    if len(column_ids) != contract["cols"]:
        raise ValueError("mapping column_ids cardinality must equal frozen cols")
    if any(type(identity) is not str or not identity for identity in [*row_ids, *column_ids]):
        raise ValueError("mapping identities must be nonempty strings")
    if len(set(row_ids)) != len(row_ids) or len(set(column_ids)) != len(column_ids):
        raise ValueError("mapping identities must be unique within each axis")
    observed_columns = _integer(mapping["observed_column_count"], "observed_column_count")
    reserved_columns = _integer(
        mapping["reserved_empty_column_count"], "reserved_empty_column_count"
    )
    if observed_columns + reserved_columns != len(column_ids):
        raise ValueError("observed and reserved column counts must cover column_ids")
    mapping_digest = _sha256(mapping["mapping_sha256"], "mapping.mapping_sha256")
    mapping_core = {key: value for key, value in mapping.items() if key != "mapping_sha256"}
    if mapping_digest != hashlib.sha256(_canonical_json_bytes(mapping_core)).hexdigest():
        raise ValueError("mapping_sha256 does not bind the exact mapping")

    trace_summary = _object(manifest["trace"], "trace")
    _closed_keys(trace_summary, _TRACE_KEYS, "trace")
    vector_binding = _object(manifest["query_vector"], "query_vector binding")
    _closed_keys(vector_binding, _QUERY_VECTOR_BINDING_KEYS, "query_vector binding")
    if vector_binding != {
        "schema_version": PUBLICATION_QUERY_VECTOR_SCHEMA,
        "filename": "publication-query-vector.json",
        "length": contract["cols"],
        "query_vector_sha256": vector_binding["query_vector_sha256"],
    }:
        raise ValueError("query-vector manifest binding is not frozen")
    _sha256(vector_binding["query_vector_sha256"], "query_vector_sha256")
    _sha256(manifest["trace_jsonl_sha256"], "trace_jsonl_sha256")
    _sha256(manifest["accepted_raw_event_sha256"], "accepted_raw_event_sha256")
    operation_counts = _object(manifest["operation_counts"], "operation_counts")
    _closed_keys(
        operation_counts,
        frozenset({"insert", "modify", "delete", "clipped-no-op"}),
        "operation_counts",
    )
    _validate_nonnegative_count_map(operation_counts, "operation_counts")
    filter_counts = _validate_nonnegative_count_map(
        manifest["filter_counts"],
        "filter_counts",
        allowed_keys=_FILTER_COUNT_KEYS,
        sparse=True,
    )
    source_event_type_counts = _validate_nonnegative_count_map(
        manifest["source_event_type_counts"],
        "source_event_type_counts",
        allowed_keys=_SOURCE_EVENT_TYPES[dataset_id],
        sparse=True,
    )
    schema_valid_raw_events = _integer(
        manifest["schema_valid_raw_events"], "schema_valid_raw_events"
    )
    accepted_raw_events = _integer(
        trace_summary["accepted_raw_events"], "trace.accepted_raw_events"
    )
    mapping_prefix_events = _integer(
        mapping["mapping_prefix_events"], "mapping.mapping_prefix_events"
    )
    if schema_valid_raw_events != (
        mapping_prefix_events + accepted_raw_events + sum(filter_counts.values())
    ):
        raise ValueError(
            "schema_valid_raw_events must equal mapping-prefix, accepted, and filtered events"
        )
    if sum(source_event_type_counts.values()) != accepted_raw_events:
        raise ValueError("source_event_type_counts must sum to accepted raw events")
    realized_bounds = _object(manifest["realized_bounds"], "realized_bounds")
    _closed_keys(
        realized_bounds,
        frozenset({"coefficient_min", "coefficient_max", "peak_row_nonzeros"}),
        "realized_bounds",
    )
    if realized_bounds["coefficient_min"] != 0:
        raise ValueError("realized coefficient minimum must be exactly zero")
    coefficient_max = _integer(
        realized_bounds["coefficient_max"], "realized_bounds.coefficient_max"
    )
    peak_row_nonzeros = _integer(
        realized_bounds["peak_row_nonzeros"], "realized_bounds.peak_row_nonzeros"
    )
    if coefficient_max > contract["coefficient_cap"]:
        raise ValueError("realized coefficient maximum exceeds the frozen cap")
    if peak_row_nonzeros > contract["maximum_row_nonzeros"]:
        raise ValueError("realized peak row nonzeros exceeds the frozen limit")
    eligibility = _object(manifest["eligibility"], "eligibility")
    _closed_keys(
        eligibility,
        frozenset({"eligible", "failure_reasons", "replacement_allowed"}),
        "eligibility",
    )
    _boolean(eligibility["eligible"], "eligibility.eligible")
    failure_reasons = _list(eligibility["failure_reasons"], "eligibility.failure_reasons")
    if any(type(reason) is not str or not reason for reason in failure_reasons):
        raise ValueError("eligibility failure reasons must be nonempty strings")
    if eligibility["replacement_allowed"] is not False:
        raise ValueError("trace replacement must be forbidden")
    if eligibility["eligible"] != (failure_reasons == []):
        raise ValueError("eligibility boolean must agree with the closed failure-reason list")
    return manifest


def _event_provenance(value: object, field: str) -> TransitionEventProvenance:
    payload = _object(value, field)
    _closed_keys(payload, _EVENT_PROVENANCE_KEYS, field)
    return TransitionEventProvenance(
        canonical_raw_event_ordinal=_integer(
            payload["canonical_raw_event_ordinal"], f"{field}.canonical_raw_event_ordinal"
        ),
        source_timestamp_utc=_string(
            payload["source_timestamp_utc"], f"{field}.source_timestamp_utc"
        ),
        source_file_ordinal=_integer(
            payload["source_file_ordinal"], f"{field}.source_file_ordinal"
        ),
        within_file_ordinal=_integer(
            payload["within_file_ordinal"], f"{field}.within_file_ordinal"
        ),
        source_event_type=_string(payload["source_event_type"], f"{field}.source_event_type"),
    )


def _transition(
    value: object,
    *,
    manifest: dict[str, object],
    line_number: int,
) -> PublicationTransition:
    field = f"publication-trace.jsonl line {line_number}"
    payload = _object(value, field)
    _closed_keys(payload, _TRANSITION_KEYS, field)
    if payload["schema_version"] != PUBLICATION_TRANSITION_SCHEMA:
        raise ValueError(f"{field} schema must be {PUBLICATION_TRANSITION_SCHEMA}")
    for name in ("dataset_id", "dataset_release", "semantics", "source_partition"):
        if payload[name] != manifest[name]:
            raise ValueError(f"{field}.{name} does not match the manifest")
    provenance = _object(manifest["repository_provenance"], "repository_provenance")
    if payload["repository_provenance_sha256"] != provenance["repository_provenance_sha256"]:
        raise ValueError(f"{field} repository provenance does not match the manifest")
    contract = _object(manifest["frozen_contract"], "frozen_contract")
    row_index = _integer(payload["row_index"], f"{field}.row_index")
    column_index = _integer(payload["column_index"], f"{field}.column_index")
    mapping = _object(manifest["mapping"], "mapping")
    if row_index >= len(_list(mapping["row_ids"], "mapping.row_ids")):
        raise ValueError(f"{field}.row_index is outside the mapped rows")
    if column_index >= contract["cols"]:
        raise ValueError(f"{field}.column_index is outside frozen cols")
    before = _integer(payload["before"], f"{field}.before")
    after = _integer(payload["after"], f"{field}.after")
    if max(before, after) > contract["coefficient_cap"]:
        raise ValueError(f"{field} coefficient exceeds the frozen cap")
    expected_operation = (
        "clipped-no-op"
        if before == after
        else "insert"
        if before == 0
        else "delete"
        if after == 0
        else "modify"
    )
    if payload["operation"] != expected_operation:
        raise ValueError(f"{field}.operation does not match before/after")
    return PublicationTransition(
        schema_version=PUBLICATION_TRANSITION_SCHEMA,
        dataset_id=str(payload["dataset_id"]),
        dataset_release=str(payload["dataset_release"]),
        semantics=str(payload["semantics"]),
        source_partition=int(payload["source_partition"]),
        repository_provenance_sha256=str(payload["repository_provenance_sha256"]),
        accepted_event_ordinal=_integer(
            payload["accepted_event_ordinal"], f"{field}.accepted_event_ordinal"
        ),
        transition_ordinal=_integer(payload["transition_ordinal"], f"{field}.transition_ordinal"),
        transition_cause=_string(payload["transition_cause"], f"{field}.transition_cause"),
        trigger_event=_event_provenance(payload["trigger_event"], f"{field}.trigger_event"),
        subject_event=_event_provenance(payload["subject_event"], f"{field}.subject_event"),
        logical_time_numerator=_integer(
            payload["logical_time_numerator"], f"{field}.logical_time_numerator"
        ),
        logical_time_denominator=_integer(
            payload["logical_time_denominator"],
            f"{field}.logical_time_denominator",
            minimum=1,
        ),
        row_index=row_index,
        column_index=column_index,
        operation=str(payload["operation"]),
        before=before,
        after=after,
    )


def _validate_group(group: list[PublicationTransition], expected_ordinal: int) -> _TraceGroup:
    if not group:
        raise AssertionError("trace group validator received an empty group")
    if any(record.accepted_event_ordinal != expected_ordinal for record in group):
        raise ValueError("accepted-event ordinals must be contiguous from zero")
    if any(record.logical_time_numerator != expected_ordinal for record in group):
        raise ValueError("logical time numerator must equal accepted-event ordinal")
    denominators = {record.logical_time_denominator for record in group}
    if denominators != {128}:
        raise ValueError("all transition records must use the exact 128 Hz clock")
    order = tuple((record.transition_ordinal, record.transition_cause) for record in group)
    semantics = group[0].semantics
    if semantics == "T1" and order != ((0, "admission"),):
        raise ValueError("T1 groups must contain exactly one admission transition")
    if semantics == "T2" and order not in (
        ((1, "admission"),),
        ((0, "expiry"), (1, "admission")),
    ):
        raise ValueError("T2 groups must order an optional expiry before one admission")
    admission = group[-1]
    if admission.subject_event != admission.trigger_event:
        raise ValueError("admission subject provenance must equal its trigger provenance")
    if len(group) == 2 and group[0].trigger_event != admission.trigger_event:
        raise ValueError("T2 expiry and admission must bind the same incoming trigger event")
    return _TraceGroup(
        accepted_ordinal=expected_ordinal,
        logical_time=Fraction(expected_ordinal, 128),
        transitions=tuple(group),
    )


def _parse_trace(raw: bytes, manifest: dict[str, object]) -> tuple[_TraceGroup, ...]:
    if not raw:
        raise ValueError("publication-trace.jsonl must not be empty")
    groups: list[_TraceGroup] = []
    current: list[PublicationTransition] = []
    current_ordinal: int | None = None
    state: dict[tuple[int, int], int] = {}
    for line_number, line in enumerate(raw.splitlines(keepends=True), start=1):
        if not line.endswith(b"\n") or line == b"\n":
            raise ValueError("publication-trace.jsonl must contain canonical nonempty JSON lines")
        record = _transition(
            _decode_canonical_json(line, f"publication-trace.jsonl line {line_number}"),
            manifest=manifest,
            line_number=line_number,
        )
        if current_ordinal is None:
            current_ordinal = record.accepted_event_ordinal
        elif record.accepted_event_ordinal != current_ordinal:
            groups.append(_validate_group(current, len(groups)))
            current = []
            current_ordinal = record.accepted_event_ordinal
        coordinate = (record.row_index, record.column_index)
        if state.get(coordinate, 0) != record.before:
            raise ValueError("transition before value does not match replayed matrix state")
        if record.after == 0:
            state.pop(coordinate, None)
        else:
            state[coordinate] = record.after
        current.append(record)
    groups.append(_validate_group(current, len(groups)))
    return tuple(groups)


def _canonical_raw_event_payload(
    event: TransitionEventProvenance,
    *,
    canonical_source_id: str,
    canonical_target_id: str,
) -> dict[str, object]:
    return {
        "schema_version": CANONICAL_RAW_EVENT_SCHEMA,
        "timestamp_utc": event.source_timestamp_utc,
        "source_file_ordinal": event.source_file_ordinal,
        "within_file_ordinal": event.within_file_ordinal,
        "canonical_source_id": canonical_source_id,
        "canonical_target_id": canonical_target_id,
        "source_event_type": event.source_event_type,
    }


def _validate_transition_semantics(
    manifest: dict[str, object],
    groups: tuple[_TraceGroup, ...],
) -> None:
    """Replay the raw-count transform, including the exact T2 FIFO of length K."""

    contract = _object(manifest["frozen_contract"], "frozen_contract")
    mapping = _object(manifest["mapping"], "mapping")
    row_ids = _list(mapping["row_ids"], "mapping.row_ids")
    column_ids = _list(mapping["column_ids"], "mapping.column_ids")
    observed_column_count = int(mapping["observed_column_count"])
    coefficient_cap = int(contract["coefficient_cap"])
    event_window_size = int(contract["event_window_size"])
    raw_counts: dict[tuple[int, int], int] = {}
    fifo: deque[tuple[TransitionEventProvenance, int, int]] = deque()
    accepted_hasher = hashlib.sha256()
    source_event_type_counts: Counter[str] = Counter()
    previous_trigger_key: tuple[str, int, int] | None = None
    previous_raw_event_ordinal: int | None = None

    def apply(record: PublicationTransition, delta: int) -> None:
        coordinate = (record.row_index, record.column_index)
        raw_before = raw_counts.get(coordinate, 0)
        expected_before = min(coefficient_cap, raw_before)
        raw_after = raw_before + delta
        if raw_after < 0:
            raise ValueError("raw-count replay became negative")
        expected_after = min(coefficient_cap, raw_after)
        if (record.before, record.after) != (expected_before, expected_after):
            raise ValueError(
                "transition before/after does not equal the exact capped raw-count transform"
            )
        if raw_after:
            raw_counts[coordinate] = raw_after
        else:
            raw_counts.pop(coordinate, None)

    for group in groups:
        admission = group.transitions[-1]
        trigger = admission.trigger_event
        trigger_key = (
            trigger.source_timestamp_utc,
            trigger.source_file_ordinal,
            trigger.within_file_ordinal,
        )
        if previous_trigger_key is not None and trigger_key <= previous_trigger_key:
            raise ValueError(
                "accepted admission triggers must be strictly chronological and unique"
            )
        if (
            previous_raw_event_ordinal is not None
            and trigger.canonical_raw_event_ordinal <= previous_raw_event_ordinal
        ):
            raise ValueError("accepted canonical raw-event ordinals must be strictly increasing")
        previous_trigger_key = trigger_key
        previous_raw_event_ordinal = trigger.canonical_raw_event_ordinal
        if admission.column_index >= observed_column_count:
            raise ValueError("reserved-empty columns must never occur in a transition")

        if manifest["semantics"] == "T2":
            if group.accepted_ordinal < event_window_size:
                if len(group.transitions) != 1:
                    raise ValueError("T2 groups before K must contain exactly one admission")
            else:
                if len(group.transitions) != 2:
                    raise ValueError("T2 groups at or after K must contain expiry then admission")
                expiry = group.transitions[0]
                expected_subject, expected_row, expected_col = fifo.popleft()
                if expiry.subject_event != expected_subject:
                    raise ValueError(
                        "T2 expiry subject must equal the FIFO admission K groups earlier"
                    )
                if (expiry.row_index, expiry.column_index) != (expected_row, expected_col):
                    raise ValueError(
                        "T2 expiry coordinate must equal the FIFO admission coordinate"
                    )
                if expiry.column_index >= observed_column_count:
                    raise ValueError("reserved-empty columns must never occur in a transition")
                apply(expiry, -1)
        apply(admission, 1)
        if manifest["semantics"] == "T2":
            fifo.append((trigger, admission.row_index, admission.column_index))
            if len(fifo) > event_window_size:
                raise AssertionError("T2 FIFO exceeded the frozen event-window size")

        canonical_source_id = str(row_ids[admission.row_index])
        canonical_target_id = str(column_ids[admission.column_index])
        accepted_hasher.update(
            _canonical_json_bytes(
                _canonical_raw_event_payload(
                    trigger,
                    canonical_source_id=canonical_source_id,
                    canonical_target_id=canonical_target_id,
                )
            )
        )
        source_event_type_counts[trigger.source_event_type] += 1

    if accepted_hasher.hexdigest() != manifest["accepted_raw_event_sha256"]:
        raise ValueError("accepted_raw_event_sha256 does not bind the replayed admissions")
    if dict(sorted(source_event_type_counts.items())) != manifest["source_event_type_counts"]:
        raise ValueError("source_event_type_counts do not match the replayed admissions")


def _validate_trace_summary(manifest: dict[str, object], groups: tuple[_TraceGroup, ...]) -> None:
    records = tuple(record for group in groups for record in group.transitions)
    trace = _object(manifest["trace"], "trace")
    contract = _object(manifest["frozen_contract"], "frozen_contract")
    operation_counts = _object(manifest["operation_counts"], "operation_counts")
    logical_changes = sum(record.operation != "clipped-no-op" for record in records)
    clipped_noops = len(records) - logical_changes
    expected_operation_counts = {
        operation: sum(record.operation == operation for record in records)
        for operation in ("insert", "modify", "delete", "clipped-no-op")
    }
    expected_trace = {
        "accepted_raw_events": len(groups),
        "clipped_noops": clipped_noops,
        "complete_publication_window_lower_bound": logical_changes
        // contract["maximum_transitions_per_microbatch_window"],
        "logical_changes": logical_changes,
        "target_reached": len(groups) == contract["target_accepted_events"],
        "transition_records": len(records),
    }
    if trace != expected_trace:
        raise ValueError("trace summary does not match the replayed transition stream")
    if operation_counts != expected_operation_counts:
        raise ValueError("operation_counts do not match the replayed transition stream")

    replayed_state: dict[tuple[int, int], int] = {}
    active_by_row: dict[int, int] = {}
    coefficient_max = 0
    peak_row_nonzeros = 0
    for record in records:
        coordinate = (record.row_index, record.column_index)
        if replayed_state.get(coordinate, 0) != record.before:
            raise ValueError("realized-bound replay does not match transition before values")
        if record.before == 0 and record.after > 0:
            active_by_row[record.row_index] = active_by_row.get(record.row_index, 0) + 1
        elif record.before > 0 and record.after == 0:
            active_by_row[record.row_index] = active_by_row.get(record.row_index, 0) - 1
        if record.after == 0:
            replayed_state.pop(coordinate, None)
        else:
            replayed_state[coordinate] = record.after
        coefficient_max = max(coefficient_max, record.after)
        peak_row_nonzeros = max(peak_row_nonzeros, active_by_row.get(record.row_index, 0))
    realized_bounds = _object(manifest["realized_bounds"], "realized_bounds")
    if realized_bounds != {
        "coefficient_min": 0,
        "coefficient_max": coefficient_max,
        "peak_row_nonzeros": peak_row_nonzeros,
    }:
        raise ValueError("realized_bounds do not match the replayed transition stream")

    eligibility = _object(manifest["eligibility"], "eligibility")
    if eligibility["eligible"] is True and (
        expected_trace["target_reached"] is not True
        or logical_changes < contract["minimum_logical_changes"]
        or expected_trace["complete_publication_window_lower_bound"]
        < contract["minimum_complete_window_lower_bound"]
        or peak_row_nonzeros > contract["maximum_row_nonzeros"]
    ):
        raise ValueError("eligible trace does not satisfy its frozen numeric gates")


def _validate_query_vector(
    raw: bytes,
    *,
    manifest: dict[str, object],
) -> tuple[int, ...]:
    payload = _object(_decode_canonical_json(raw, "publication-query-vector.json"), "query vector")
    _closed_keys(payload, _QUERY_VECTOR_KEYS, "query vector")
    mapping = _object(manifest["mapping"], "mapping")
    contract = _object(manifest["frozen_contract"], "frozen_contract")
    expected = _publication_query_vector_payload(
        dataset_id=str(manifest["dataset_id"]),
        dataset_release=str(manifest["dataset_release"]),
        semantics=str(manifest["semantics"]),
        source_partition=int(manifest["source_partition"]),
        mapping_sha256=str(mapping["mapping_sha256"]),
        length=int(contract["cols"]),
    )
    if payload != expected:
        raise ValueError("query vector does not match the frozen deterministic generator")
    values = _list(payload["values"], "query vector.values")
    if any(type(value) is not int or value not in {-1, 0, 1} for value in values):
        raise ValueError("query vector values must be exact ternary integers")
    return tuple(int(value) for value in values)


def _validate_production_trace_contract(
    manifest: dict[str, object],
    groups: tuple[_TraceGroup, ...],
) -> None:
    acquisition_binding = _object(manifest["acquisition_binding"], "acquisition_binding")
    acquisition_provenance = _object(
        acquisition_binding["repository_provenance"],
        "acquisition_binding.repository_provenance",
    )
    if acquisition_provenance["verification_mode"] != (
        "hardened-acquisition-role-git-object-worktree-v1"
    ):
        raise ValueError(
            "production trace contract requires hardened central acquisition provenance"
        )
    contract = _object(manifest["frozen_contract"], "frozen_contract")
    exact_contract_values: dict[str, object] = {
        "rows": 4_096,
        "cols": 8_193,
        "mapping_prefix_numerator": 1,
        "mapping_prefix_denominator": 10,
        "mapping_tie_break": "canonical-id-ascending",
        "source_partition_rule": ("big-endian-SHA256(dataset_release||canonical_source_id)-mod-5"),
        "reserved_column_padding_max_fraction": "1/10",
        "coefficient_cap": 7,
        "event_window_size": 32_768,
        "t2_transition_order": "expiry-before-admission",
        "t2_expiry_event_provenance": (
            "trigger-event-is-incoming-raw-event;subject-event-is-expired-raw-event"
        ),
        "target_accepted_events": 131_072,
        "minimum_logical_changes": 65_536,
        "microbatch_cap": 64,
        "microbatch_cap_unit": "emitted-logical-set-transitions",
        "atomic_transition_group_policy": "accepted-event-group-never-split",
        "minimum_complete_window_lower_bound": 1_000,
        "complete_publication_window_count_rule": (
            "floor(emitted_logical_changes/maximum-transitions-per-atomic-window)-"
            "conservative-lower-bound"
        ),
        "maximum_row_nonzeros": 4_096,
    }
    mismatches = [
        name for name, expected in exact_contract_values.items() if contract[name] != expected
    ]
    maximum_atomic_group_size = 1 if manifest["semantics"] == "T1" else 2
    if contract["maximum_atomic_group_size"] != maximum_atomic_group_size:
        mismatches.append("maximum_atomic_group_size")
    if contract["maximum_transitions_per_microbatch_window"] != 63 + maximum_atomic_group_size:
        mismatches.append("maximum_transitions_per_microbatch_window")
    if mismatches:
        raise ValueError(
            "production trace contract has non-frozen fields: " + ", ".join(sorted(mismatches))
        )

    provenance = _object(manifest["repository_provenance"], "repository_provenance")
    behavior_digests = _object(
        provenance["behavior_source_blob_sha256"], "behavior_source_blob_sha256"
    )
    if provenance["verification_mode"] != "hardened-trace-role-git-object-worktree-v1" or set(
        behavior_digests
    ) != set(_PUBLICATION_BEHAVIOR_PATHS):
        raise ValueError(
            "production trace contract requires clean HEAD and the exact behavior-path set"
        )

    mapping = _object(manifest["mapping"], "mapping")
    if (
        len(_list(mapping["row_ids"], "mapping.row_ids")) != 4_096
        or len(_list(mapping["column_ids"], "mapping.column_ids")) != 8_193
    ):
        raise ValueError("production trace contract requires the exact mapped dimensions")

    vector_generation = _object(contract["query_vector_generation"], "query_vector_generation")
    expected_vector_generation = {
        "schema_version": PUBLICATION_QUERY_VECTOR_SCHEMA,
        "seed": 2_026_082_302,
        "length": 8_193,
        "coefficient_bound": 1,
        "generation": "shake256-per-coordinate-rejection-sampling",
        "forced_boundary_entries": {"0": 1, "8192": -1},
        "reuse_scope": "one-vector-per-paired-analysis-unit-all-query-arrivals",
        "evaluation_query_plaintext_public": True,
        "query_confidentiality_evidence_allowed": False,
        "security_randomness_claim_allowed": False,
        "query_distribution_claim_allowed": False,
    }
    if vector_generation != expected_vector_generation:
        raise ValueError("production trace contract query-vector generation is not exact")
    if manifest["dataset_id"] == "nyc-tlc-yellow-2022":
        normalization = _object(manifest["normalization_contract"], "normalization_contract")
        if not _validate_nyc_parser_identity(normalization["parser_runtime_identity"]):
            raise ValueError("production trace contract rejects the test-only NYC parser")

    trace_summary = _object(manifest["trace"], "trace")
    eligibility = _object(manifest["eligibility"], "eligibility")
    if (
        len(groups) != 131_072
        or trace_summary["accepted_raw_events"] != 131_072
        or trace_summary["target_reached"] is not True
        or trace_summary["logical_changes"] < 65_536
        or trace_summary["complete_publication_window_lower_bound"] < 1_000
        or eligibility != {"eligible": True, "failure_reasons": [], "replacement_allowed": False}
    ):
        raise ValueError(
            "production trace contract requires exact N=131072 and all eligibility gates"
        )


def _load_publication_trace_bundle(
    trace_dir: Path,
    *,
    production: bool,
) -> ValidatedPublicationTrace:
    """Implement the production loader and its explicitly non-authoritative test seam."""

    if not isinstance(trace_dir, Path):
        raise TypeError("trace_dir must be a pathlib.Path")
    try:
        directory_mode = trace_dir.lstat().st_mode
    except OSError as error:
        raise ValueError("trace_dir must name an existing directory") from error
    if trace_dir.is_symlink() or not stat.S_ISDIR(directory_mode):
        raise ValueError("trace_dir must name a non-symlink directory")
    actual_names = {entry.name for entry in trace_dir.iterdir()}
    expected_names = set(_BUNDLE_FILENAMES)
    if actual_names != expected_names:
        raise ValueError(
            "trace bundle tree is closed; "
            f"missing={sorted(expected_names - actual_names)}, "
            f"extra={sorted(actual_names - expected_names)}"
        )

    checksums = _parse_checksums(
        _read_regular_file(trace_dir / "checksums.sha256", "checksums.sha256")
    )
    manifest_raw = _read_regular_file(
        trace_dir / "publication-trace-manifest.json", "publication-trace-manifest.json"
    )
    trace_raw = _read_regular_file(trace_dir / "publication-trace.jsonl", "publication-trace.jsonl")
    vector_raw = _read_regular_file(
        trace_dir / "publication-query-vector.json", "publication-query-vector.json"
    )
    observed = {
        "publication-trace-manifest.json": hashlib.sha256(manifest_raw).hexdigest(),
        "publication-trace.jsonl": hashlib.sha256(trace_raw).hexdigest(),
        "publication-query-vector.json": hashlib.sha256(vector_raw).hexdigest(),
    }
    if observed != checksums:
        raise ValueError("checksums.sha256 does not match the exact trace artifacts")

    manifest = _validate_manifest(
        _decode_canonical_json(manifest_raw, "publication-trace-manifest.json")
    )
    if manifest["trace_jsonl_sha256"] != observed["publication-trace.jsonl"]:
        raise ValueError("trace manifest does not bind publication-trace.jsonl")
    vector_binding = _object(manifest["query_vector"], "query_vector binding")
    if vector_binding["query_vector_sha256"] != observed["publication-query-vector.json"]:
        raise ValueError("trace manifest does not bind publication-query-vector.json")
    groups = _parse_trace(trace_raw, manifest)
    _validate_transition_semantics(manifest, groups)
    _validate_trace_summary(manifest, groups)
    query_vector = _validate_query_vector(vector_raw, manifest=manifest)
    if production:
        _validate_production_trace_contract(manifest, groups)
    contract = _object(manifest["frozen_contract"], "frozen_contract")
    mapping = _object(manifest["mapping"], "mapping")
    provenance = _object(manifest["repository_provenance"], "repository_provenance")
    eligibility = _object(manifest["eligibility"], "eligibility")
    validated = ValidatedPublicationTrace(
        trace_dir=trace_dir,
        dataset_id=str(manifest["dataset_id"]),
        dataset_release=str(manifest["dataset_release"]),
        semantics=str(manifest["semantics"]),
        source_partition=int(manifest["source_partition"]),
        repository_provenance_sha256=str(provenance["repository_provenance_sha256"]),
        mapping_sha256=str(mapping["mapping_sha256"]),
        accepted_group_count=len(groups),
        transition_count=sum(len(group.transitions) for group in groups),
        clock_denominator=128,
        microbatch_max_updates=64,
        coefficient_cap=int(contract["coefficient_cap"]),
        rows=int(contract["rows"]),
        cols=int(contract["cols"]),
        query_vector=query_vector,
        manifest_sha256=observed["publication-trace-manifest.json"],
        trace_jsonl_sha256=observed["publication-trace.jsonl"],
        query_vector_sha256=observed["publication-query-vector.json"],
        eligible=bool(eligibility["eligible"]),
        _groups=groups,
        _validation_token=_PRODUCTION_TRACE_TOKEN if production else _TEST_TRACE_TOKEN,
    )
    issued = _ISSUED_PRODUCTION_TRACES if production else _ISSUED_TEST_TRACES
    issued[id(validated)] = validated
    return validated


def load_publication_trace_bundle(trace_dir: Path) -> ValidatedPublicationTrace:
    """Validate one exact, eligible production-shaped v6/v3 trace bundle.

    The returned capability binds this local validation result. It is not acquisition,
    repository, workflow, or publication authority.
    """

    return _load_publication_trace_bundle(trace_dir, production=True)


def _load_publication_trace_bundle_for_test(trace_dir: Path) -> ValidatedPublicationTrace:
    """Private fixture seam; its result has no production capability."""

    return _load_publication_trace_bundle(trace_dir, production=False)


def _accepted_group_phase_ranges(total: int) -> tuple[AcceptedGroupPhaseRange, ...]:
    if total < 10:
        raise ValueError("publication traces need at least ten accepted-event groups")
    warmup_end = total // 10
    tuning_end = total * 4 // 10
    return (
        AcceptedGroupPhaseRange("warmup", 0, warmup_end),
        AcceptedGroupPhaseRange("tuning", warmup_end, tuning_end),
        AcceptedGroupPhaseRange("heldout", tuning_end, total),
    )


def _program_header_payload(program: AcceptedGroupProgram) -> dict[str, object]:
    ranges = [
        {"name": phase.name, "start": phase.start, "end": phase.end}
        for phase in program.phase_ranges
    ]
    ranges_sha256 = hashlib.sha256(_canonical_json_bytes(ranges)).hexdigest()
    return {
        "schema_version": program.schema_version,
        "record_kind": "accepted-event-schedule-header",
        "dataset_id": program.trace.dataset_id,
        "dataset_release": program.trace.dataset_release,
        "semantics": program.trace.semantics,
        "source_partition": program.trace.source_partition,
        "trace_manifest_sha256": program.trace.manifest_sha256,
        "trace_jsonl_sha256": program.trace.trace_jsonl_sha256,
        "query_vector_sha256": program.trace.query_vector_sha256,
        "accepted_group_count": program.accepted_group_count,
        "clock_denominator": program.trace.clock_denominator,
        "rho": {
            "numerator": program.rho.numerator,
            "denominator": program.rho.denominator,
        },
        "phase_ranges": ranges,
        "phase_ranges_sha256": ranges_sha256,
        "event_grammar": "SET*-then-TICK-then-QUERY-RUN-then-optional-PHASE-BOUNDARY",
        "query_run_expansion": "consecutive-query-ordinals-at-group-logical-time",
        "microbatch_max_updates": program.trace.microbatch_max_updates,
        "total_set_count": program.total_set_count,
        "total_query_count": program.total_query_count,
        "scheduled_event_count": program.scheduled_event_count,
    }


def _scheduled_group_payload(group: ScheduledAcceptedGroup) -> dict[str, object]:
    events: list[dict[str, object]] = [
        {
            "kind": "set",
            "transition_ordinal": scheduled_set.transition_ordinal,
            "transition_cause": scheduled_set.transition_cause,
            "row": scheduled_set.row,
            "col": scheduled_set.col,
            "before": scheduled_set.before,
            "after": scheduled_set.after,
            "value": scheduled_set.after,
        }
        for scheduled_set in group.sets
    ]
    events.append({"kind": "tick"})
    events.append(
        {
            "kind": "query-run",
            "first_query_ordinal": group.query_run.first_query_ordinal,
            "count": group.query_run.count,
        }
    )
    if group.phase_close_after is not None:
        events.append({"kind": "phase-boundary", "closed_phase": group.phase_close_after})
    return {
        "schema_version": ACCEPTED_EVENT_SCHEDULE_SCHEMA,
        "record_kind": "accepted-event-group",
        "accepted_event_ordinal": group.accepted_ordinal,
        "phase": group.phase,
        "logical_time": {
            "numerator": group.logical_time.numerator,
            "denominator": group.logical_time.denominator,
        },
        "events": events,
    }


def _phase_for_ordinal(
    phase_ranges: tuple[AcceptedGroupPhaseRange, ...], accepted_ordinal: int
) -> AcceptedGroupPhaseRange:
    for phase in phase_ranges:
        if phase.start <= accepted_ordinal < phase.end:
            return phase
    raise AssertionError("accepted ordinal is outside the frozen phase ranges")


def _compile_accepted_group_program(
    trace: ValidatedPublicationTrace,
    rho: Fraction,
    *,
    production: bool,
) -> AcceptedGroupProgram:
    """Compile one exact, uniquely expandable RLE schedule without QUERY expansion."""

    if type(rho) is not Fraction or rho < 0:
        raise ValueError("rho must be one exact nonnegative Fraction")
    if production and rho not in _PRODUCTION_RHO_VALUES:
        raise ValueError("production schedules require one of the nine frozen rho values")
    expected_trace_token = _PRODUCTION_TRACE_TOKEN if production else _TEST_TRACE_TOKEN
    issued_traces = _ISSUED_PRODUCTION_TRACES if production else _ISSUED_TEST_TRACES
    if (
        type(trace) is not ValidatedPublicationTrace
        or trace._validation_token is not expected_trace_token
        or issued_traces.get(id(trace)) is not trace
    ):
        raise TypeError("trace does not carry the required loader capability")
    if trace.accepted_group_count != len(trace._groups):
        raise ValueError("validated trace accepted-group count was altered")
    if trace.transition_count != sum(len(group.transitions) for group in trace._groups):
        raise ValueError("validated trace transition count was altered")
    if trace.clock_denominator != 128 or trace.microbatch_max_updates != 64:
        raise ValueError("validated trace publication clock or microbatch threshold was altered")
    expected_vector = _publication_query_vector_payload(
        dataset_id=trace.dataset_id,
        dataset_release=trace.dataset_release,
        semantics=trace.semantics,
        source_partition=trace.source_partition,
        mapping_sha256=trace.mapping_sha256,
        length=trace.cols,
    )["values"]
    if trace.query_vector != tuple(expected_vector):
        raise ValueError("validated trace query vector was altered")

    phase_ranges = _accepted_group_phase_ranges(trace.accepted_group_count)
    groups: list[ScheduledAcceptedGroup] = []
    total_set_count = 0
    for source_group in trace._groups:
        phase = _phase_for_ordinal(phase_ranges, source_group.accepted_ordinal)
        sets = tuple(
            ScheduledSet(
                transition_ordinal=record.transition_ordinal,
                transition_cause=record.transition_cause,
                row=record.row_index,
                col=record.column_index,
                before=record.before,
                after=record.after,
            )
            for record in source_group.transitions
            if record.operation != "clipped-no-op"
        )
        total_set_count += len(sets)
        queries_before = source_group.accepted_ordinal * rho.numerator // rho.denominator
        queries_after = (source_group.accepted_ordinal + 1) * rho.numerator // rho.denominator
        groups.append(
            ScheduledAcceptedGroup(
                accepted_ordinal=source_group.accepted_ordinal,
                phase=phase.name,
                logical_time=source_group.logical_time,
                sets=sets,
                query_run=ScheduledQueryRun(
                    first_query_ordinal=queries_before,
                    count=queries_after - queries_before,
                ),
                phase_close_after=phase.name
                if source_group.accepted_ordinal + 1 == phase.end
                else None,
            )
        )
    scheduled_groups = tuple(groups)
    total_query_count = trace.accepted_group_count * rho.numerator // rho.denominator
    scheduled_event_count = (
        total_set_count + trace.accepted_group_count + total_query_count + len(phase_ranges)
    )
    provisional = AcceptedGroupProgram(
        schema_version=ACCEPTED_EVENT_SCHEDULE_SCHEMA,
        trace=trace,
        rho=rho,
        phase_ranges=phase_ranges,
        accepted_group_count=trace.accepted_group_count,
        total_set_count=total_set_count,
        total_query_count=total_query_count,
        scheduled_event_count=scheduled_event_count,
        canonical_schedule_sha256="",
        _groups=scheduled_groups,
        _program_token=_PRODUCTION_PROGRAM_TOKEN if production else _TEST_PROGRAM_TOKEN,
    )
    digest = hashlib.sha256()
    for chunk in provisional.iter_canonical_bytes():
        digest.update(chunk)
    compiled = AcceptedGroupProgram(
        schema_version=provisional.schema_version,
        trace=trace,
        rho=rho,
        phase_ranges=phase_ranges,
        accepted_group_count=provisional.accepted_group_count,
        total_set_count=total_set_count,
        total_query_count=total_query_count,
        scheduled_event_count=scheduled_event_count,
        canonical_schedule_sha256=digest.hexdigest(),
        _groups=scheduled_groups,
        _program_token=_PRODUCTION_PROGRAM_TOKEN if production else _TEST_PROGRAM_TOKEN,
    )
    issued_programs = _ISSUED_PRODUCTION_PROGRAMS if production else _ISSUED_TEST_PROGRAMS
    issued_programs[id(compiled)] = compiled
    return compiled


def compile_accepted_group_program(
    trace: ValidatedPublicationTrace,
    rho: Fraction,
) -> AcceptedGroupProgram:
    """Compile an RLE schedule only from a production-validated trace capability."""

    return _compile_accepted_group_program(trace, rho, production=True)


def _compile_accepted_group_program_for_test(
    trace: ValidatedPublicationTrace,
    rho: Fraction,
) -> AcceptedGroupProgram:
    """Private small-fixture seam; its program has no production capability."""

    return _compile_accepted_group_program(trace, rho, production=False)


def _validate_program(program: AcceptedGroupProgram, *, production: bool) -> None:
    expected_program_token = _PRODUCTION_PROGRAM_TOKEN if production else _TEST_PROGRAM_TOKEN
    issued_programs = _ISSUED_PRODUCTION_PROGRAMS if production else _ISSUED_TEST_PROGRAMS
    if (
        type(program) is not AcceptedGroupProgram
        or program._program_token is not expected_program_token
        or issued_programs.get(id(program)) is not program
    ):
        raise TypeError("program does not carry the required compiler capability")
    if program.schema_version != ACCEPTED_EVENT_SCHEDULE_SCHEMA:
        raise ValueError("accepted-event program schema was altered")
    if program.accepted_group_count != len(program._groups):
        raise ValueError("accepted-event program group count was altered")
    if program.total_set_count != sum(len(group.sets) for group in program._groups):
        raise ValueError("accepted-event program SET count was altered")
    if program.total_query_count != sum(group.query_run.count for group in program._groups):
        raise ValueError("accepted-event program QUERY count was altered")
    expected_event_count = (
        program.total_set_count
        + program.accepted_group_count
        + program.total_query_count
        + len(program.phase_ranges)
    )
    if program.scheduled_event_count != expected_event_count:
        raise ValueError("accepted-event program expanded event count was altered")
    digest = hashlib.sha256()
    for chunk in program.iter_canonical_bytes():
        digest.update(chunk)
    if digest.hexdigest() != program.canonical_schedule_sha256:
        raise ValueError("canonical_schedule_sha256 does not bind the exact RLE program")


def _stream_publication_windows(
    program: AcceptedGroupProgram,
    freshness: Fraction,
    *,
    production: bool,
) -> Iterator[ExactPublicationWindow]:
    """Stream exact windows without expanding a query run or splitting an accepted group."""

    if type(freshness) is not Fraction or freshness <= 0:
        raise ValueError("freshness must be one exact positive Fraction")
    if production and freshness not in _PRODUCTION_FRESHNESS_VALUES:
        raise ValueError("production windows require one frozen publication freshness")
    _validate_program(program, production=production)

    state: dict[tuple[int, int], int] = {}
    first_before: dict[tuple[int, int], int] = {}
    touched: set[tuple[int, int]] = set()
    start_time: Fraction | None = None
    accepted_group_start: int | None = None
    window_phase: str | None = None
    set_count = 0
    query_count = 0
    window_index = 0

    def flush(
        *,
        end_time: Fraction,
        accepted_group_end: int,
        reason: str,
    ) -> ExactPublicationWindow | None:
        nonlocal start_time, accepted_group_start, window_phase
        nonlocal set_count, query_count, window_index
        if not touched and query_count == 0:
            start_time = None
            accepted_group_start = None
            window_phase = None
            set_count = 0
            return None
        if start_time is None or accepted_group_start is None or window_phase is None:
            raise AssertionError("publication window content has no exact start identity")
        updates = tuple(
            ScheduledNetUpdate(
                row=row,
                col=col,
                before=first_before[(row, col)],
                after=state.get((row, col), 0),
            )
            for row, col in sorted(touched)
            if first_before[(row, col)] != state.get((row, col), 0)
        )
        window = ExactPublicationWindow(
            index=window_index,
            phase=window_phase,
            accepted_group_start=accepted_group_start,
            accepted_group_end=accepted_group_end,
            start_time=start_time,
            end_time=end_time,
            set_count=set_count,
            updates=updates,
            query_count=query_count,
            reason=reason,
        )
        window_index += 1
        first_before.clear()
        touched.clear()
        start_time = None
        accepted_group_start = None
        window_phase = None
        set_count = 0
        query_count = 0
        return window

    for expected_ordinal, group in enumerate(program):
        if group.accepted_ordinal != expected_ordinal:
            raise ValueError("accepted-event program ordinals must be contiguous from zero")
        if start_time is not None and touched and group.logical_time - start_time >= freshness:
            window = flush(
                end_time=start_time + freshness,
                accepted_group_end=group.accepted_ordinal,
                reason="freshness",
            )
            if window is not None:
                yield window

        for scheduled_set in group.sets:
            coordinate = (scheduled_set.row, scheduled_set.col)
            observed_before = state.get(coordinate, 0)
            if observed_before != scheduled_set.before:
                raise ValueError("scheduled SET before value does not match continuous state")
            if start_time is None:
                start_time = group.logical_time
                accepted_group_start = group.accepted_ordinal
                window_phase = group.phase
            elif window_phase != group.phase:
                raise ValueError("a publication window must not cross an accepted-group phase")
            if coordinate not in first_before:
                first_before[coordinate] = observed_before
            touched.add(coordinate)
            if scheduled_set.after == 0:
                state.pop(coordinate, None)
            else:
                state[coordinate] = scheduled_set.after
            set_count += 1

        if group.query_run.count:
            if start_time is None:
                start_time = group.logical_time
                accepted_group_start = group.accepted_ordinal
                window_phase = group.phase
            elif window_phase != group.phase:
                raise ValueError("a publication window must not cross an accepted-group phase")
            query_count += group.query_run.count

        if query_count:
            window = flush(
                end_time=group.logical_time,
                accepted_group_end=group.accepted_ordinal + 1,
                reason="query",
            )
            if window is not None:
                yield window

        if group.phase_close_after is not None:
            if group.phase_close_after != group.phase:
                raise ValueError("phase boundary must close the group phase")
            window = flush(
                end_time=group.logical_time,
                accepted_group_end=group.accepted_ordinal + 1,
                reason=f"phase-boundary:{group.phase_close_after}",
            )
            if window is not None:
                yield window
        elif set_count >= program.trace.microbatch_max_updates:
            window = flush(
                end_time=group.logical_time,
                accepted_group_end=group.accepted_ordinal + 1,
                reason="microbatch",
            )
            if window is not None:
                yield window

    if touched or query_count:
        raise ValueError("heldout phase must end with one explicit boundary close")


def stream_publication_windows(
    program: AcceptedGroupProgram,
    freshness: Fraction,
) -> Iterator[ExactPublicationWindow]:
    """Stream windows only from a production-compiled schedule capability."""

    yield from _stream_publication_windows(program, freshness, production=True)


def _stream_publication_windows_for_test(
    program: AcceptedGroupProgram,
    freshness: Fraction,
) -> Iterator[ExactPublicationWindow]:
    """Private small-fixture seam; emitted windows have no production capability."""

    yield from _stream_publication_windows(program, freshness, production=False)


__all__ = [
    "ACCEPTED_EVENT_SCHEDULE_SCHEMA",
    "AcceptedGroupPhaseRange",
    "AcceptedGroupProgram",
    "ExactPublicationWindow",
    "ScheduledAcceptedGroup",
    "ScheduledNetUpdate",
    "ScheduledQueryRun",
    "ScheduledSet",
    "ValidatedPublicationTrace",
    "compile_accepted_group_program",
    "load_publication_trace_bundle",
    "stream_publication_windows",
]
