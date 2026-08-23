"""Fail-closed production of one publication Day1B paired analysis unit.

The production interface is intentionally two paths deep. Candidate identities, source
authority, resource limits, exact scheduling, and protocol-object serialization stay behind
that interface. The repository has not frozen all of those authorities yet, so production
currently stops before creating output. A typed private seam exercises the complete unit
builder without weakening that production HOLD.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import asdict, dataclass
from fractions import Fraction
from pathlib import Path
from typing import Protocol

from dynamic_cssc.day1_registry import (
    Day1CandidateCatalog,
    Day1CandidateRegistrationError,
    RegisteredCandidate,
    repository_day1_candidate_catalog,
)
from dynamic_cssc.evidence_compatibility import (
    EvidenceCompatibilityError,
    EvidenceRole,
    capture_behavior_inventory,
    verify_current_role_source,
)
from dynamic_cssc.publication_schedule import (
    ACCEPTED_EVENT_SCHEDULE_SCHEMA,
    AcceptedGroupPhaseRange,
    AcceptedGroupProgram,
    ExactPublicationWindow,
    ValidatedPublicationTrace,
    compile_accepted_group_program,
    load_publication_trace_bundle,
    stream_publication_windows,
)
from dynamic_cssc.publication_statistics import (
    ABLATION_CANDIDATE_ID,
    CELL_BINDING_SCHEMA,
    DATASET_IDS,
    FIXED_CANDIDATE_IDS,
    FRESHNESS_VALUES,
    HELDOUT_RECORD_SCHEMA,
    PRIMITIVE_NAMES,
    QUERY_VECTOR_SCHEMA,
    REFERENCE_CANDIDATE_IDS,
    RHO_VALUES,
    SEMANTICS,
    TRACE_UNIT_SCHEMA,
    canonical_json_bytes,
)
from dynamic_cssc.publication_traces import ACQUISITION_TRACE_BINDING_SCHEMA

DAY1B_UNIT_SCHEMA = "dynamic-cssc-publication-day1b-unit-v1"
DAY1B_UNIT_FRAGMENT_SCHEMA = "dynamic-cssc-publication-day1b-unit-fragment-v1"
DAY1B_SERIALIZATION_LEDGER_SCHEMA = (
    "dynamic-cssc-publication-day1b-serialized-protocol-object-ledger-v1"
)
DAY1B_RESOURCE_POLICY_SCHEMA = "dynamic-cssc-publication-day1b-resource-policy-v1"
DAY1B_REPLAY_RECEIPT_SCHEMA = "dynamic-cssc-publication-day1b-trace-replay-receipt-v1"

_MANIFEST_FILENAME = "publication-day1b-unit-manifest.json"
_FRAGMENT_FILENAME = "publication-heldout-fragment.json"
_SCHEDULE_FILENAME = "accepted-event-schedules.jsonl"
_LEDGER_FILENAME = "serialized-object-ledgers.jsonl"
_CHECKSUM_FILENAME = "SHA256SUMS"
_ARTIFACT_FILENAMES = (
    _MANIFEST_FILENAME,
    _FRAGMENT_FILENAME,
    _SCHEDULE_FILENAME,
    _LEDGER_FILENAME,
    _CHECKSUM_FILENAME,
)
_CHECKSUM_TARGETS = _ARTIFACT_FILENAMES[:-1]
_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_OUTCOMES = frozenset({"complete", "failed", "timeout", "infeasible", "missing", "ineligible"})

# Every complete physical record carries all categories, including explicit zero-object
# categories. Transaction ownership is repository-defined, never supplied by an executor.
SERIALIZED_PROTOCOL_OBJECT_CATEGORIES = (
    ("update-column-index-synchronization", "update"),
    ("update-publication-ciphertexts", "update"),
    ("update-version-plan-metadata", "update"),
    ("query-query-ciphertexts", "query"),
    ("query-result-ciphertexts", "query"),
    ("query-f1m-random-mask-ciphertexts", "query"),
    ("query-f1m-encrypted-zero-dummy-ciphertexts", "query"),
    ("query-version-plan-metadata", "query"),
    ("one-time-evaluation-key-material", "one-time"),
)


class PublicationDay1BHold(RuntimeError):
    """A required pre-dispatch publication authority is not frozen."""


@dataclass(frozen=True, slots=True)
class PublicationDay1BResourcePolicy:
    """One outcome-blind resource envelope fixed before a unit is dispatched."""

    wall_clock_seconds_per_cell: int
    resident_memory_bytes: int
    scratch_bytes_per_cell: int
    output_bytes_per_unit: int
    cells_per_shard: int
    max_concurrency: int
    candidate_retry_count: int
    infrastructure_preemption_whole_shard_rerun_limit: int
    authority: str

    def __post_init__(self) -> None:
        for field in (
            "wall_clock_seconds_per_cell",
            "resident_memory_bytes",
            "scratch_bytes_per_cell",
            "output_bytes_per_unit",
            "cells_per_shard",
            "max_concurrency",
            "candidate_retry_count",
            "infrastructure_preemption_whole_shard_rerun_limit",
        ):
            value = getattr(self, field)
            if type(value) is not int or value < 0:
                raise ValueError(f"resource_policy.{field} must be a strict nonnegative integer")
        if (
            min(
                self.wall_clock_seconds_per_cell,
                self.resident_memory_bytes,
                self.scratch_bytes_per_cell,
                self.output_bytes_per_unit,
            )
            <= 0
        ):
            raise ValueError("resource-policy wall/RAM/scratch/output limits must be positive")
        if self.cells_per_shard != 18 or self.max_concurrency != 1:
            raise ValueError("Day1B resource policy requires exactly 18 cells and concurrency one")
        if self.candidate_retry_count != 0:
            raise ValueError("Day1B candidate selective retries must be exactly zero")
        if self.infrastructure_preemption_whole_shard_rerun_limit not in {0, 1}:
            raise ValueError("whole-shard infrastructure-preemption reruns must be zero or one")
        if type(self.authority) is not str or not self.authority:
            raise ValueError("resource_policy.authority must be a nonempty string")

    def to_document(self) -> dict[str, object]:
        document = {"schema_version": DAY1B_RESOURCE_POLICY_SCHEMA, **asdict(self)}
        document["resource_policy_sha256"] = _digest(document)
        return document


@dataclass(frozen=True, slots=True)
class PublicationDay1BSerializedObject:
    """Actual canonical protocol bytes plus their exact occurrence multiplicity."""

    serialized_bytes: bytes
    multiplicity: int = 1

    def __post_init__(self) -> None:
        if type(self.serialized_bytes) is not bytes or not self.serialized_bytes:
            raise ValueError("serialized protocol objects must contain nonempty exact bytes")
        if type(self.multiplicity) is not int or self.multiplicity <= 0:
            raise ValueError("serialized protocol-object multiplicity must be positive")


@dataclass(frozen=True, slots=True)
class PublicationDay1BSerializedCategory:
    """One required protocol-object category, present even when it has zero objects."""

    category: str
    objects: tuple[PublicationDay1BSerializedObject, ...]

    def __post_init__(self) -> None:
        if type(self.category) is not str or not self.category:
            raise ValueError("serialized protocol-object category must be a nonempty string")
        if type(self.objects) is not tuple or any(
            type(item) is not PublicationDay1BSerializedObject for item in self.objects
        ):
            raise ValueError("serialized category objects must be an exact typed tuple")


@dataclass(frozen=True, slots=True)
class PublicationDay1BMeasurement:
    """One positional physical execution result; candidate identity is assigned by the core."""

    outcome: str
    failure_reason: str | None
    update_primitive_counts: tuple[int, ...] | None
    query_primitive_counts: tuple[int, ...] | None
    serialized_categories: tuple[PublicationDay1BSerializedCategory, ...] | None


@dataclass(frozen=True, slots=True)
class PublicationDay1BCellMeasurements:
    """Exact physical roster: 13 tuning references followed by 14 held-out fixed runs."""

    tuning_references: tuple[PublicationDay1BMeasurement, ...]
    heldout_fixed: tuple[PublicationDay1BMeasurement, ...]
    peak_resident_memory_bytes: int
    peak_scratch_bytes: int


@dataclass(frozen=True, slots=True)
class _PublicationScheduleAdapter:
    """Internal schedule seam with production and small typed-test adapters."""

    schema_version: str
    rho: Fraction
    phase_ranges: tuple[AcceptedGroupPhaseRange, ...]
    accepted_group_count: int
    total_set_count: int
    total_query_count: int
    canonical_schedule_sha256: str
    iter_canonical_bytes: Callable[[], Iterator[bytes]]
    stream_windows: Callable[[Fraction], Iterator[ExactPublicationWindow]]


@dataclass(frozen=True, slots=True)
class _Day1BTraceInput:
    """Already validated trace facts consumed by the private unit builder."""

    dataset_id: str
    dataset_release: str
    semantics: str
    source_partition: int
    trace_source_git_sha: str
    repository_provenance_sha256: str
    trace_manifest_sha256: str
    mapping_sha256: str
    accepted_events_sha256: str
    replay_receipt_sha256: str
    source_bundle_sha256: str
    acquisition_transaction_sha256: str | None
    source_set_sha256: str | None
    acquisition_network_authority_verified: bool
    accepted_group_count: int
    query_vector: tuple[int, ...]
    query_vector_canonical_bytes: bytes
    query_vector_sha256: str
    compile_schedule: Callable[[Fraction], _PublicationScheduleAdapter]
    trace_source_authority_verified: bool = False


@dataclass(frozen=True, slots=True)
class _Day1BSourceAuthority:
    git_sha: str
    behavior_inventory: Mapping[str, object]
    source_attestation: str


class _Day1BExecutionAdapter(Protocol):
    """Consume one cell as a stream and return the exact positional physical roster."""

    def execute_cell(
        self,
        *,
        windows: Iterator[ExactPublicationWindow],
        trace: _Day1BTraceInput,
        freshness: Fraction,
        rho: Fraction,
        candidates: tuple[RegisteredCandidate, ...],
        query_vector: tuple[int, ...],
        resource_policy: PublicationDay1BResourcePolicy,
    ) -> PublicationDay1BCellMeasurements: ...


@dataclass(frozen=True, slots=True)
class PublicationDay1BUnitBundle:
    """Paths and independently recomputed member identities of one installed unit."""

    output_dir: Path
    manifest_path: Path
    heldout_fragment_path: Path
    schedule_path: Path
    serialization_ledger_path: Path
    checksums_path: Path
    manifest_sha256: str
    heldout_fragment_sha256: str
    schedule_sha256: str
    serialization_ledger_sha256: str
    checksums_sha256: str


@dataclass(frozen=True, slots=True)
class _CellAudit:
    phase_receipts: tuple[dict[str, object], ...]


class _AuditedWindowStream:
    """Audit a one-pass schedule stream without retaining Publication Windows."""

    __slots__ = (
        "_expected_index",
        "_exhausted",
        "_iterator",
        "_phase_ranges",
        "_phase_stats",
        "_rho",
    )

    def __init__(
        self,
        windows: Iterator[ExactPublicationWindow],
        phase_ranges: tuple[AcceptedGroupPhaseRange, ...],
        rho: Fraction,
    ) -> None:
        self._iterator = iter(windows)
        self._phase_ranges = {phase.name: phase for phase in phase_ranges}
        self._phase_stats = {
            phase.name: {"window_count": 0, "set_count": 0, "query_count": 0}
            for phase in phase_ranges
        }
        self._rho = rho
        self._expected_index = 0
        self._exhausted = False

    def __iter__(self) -> _AuditedWindowStream:
        return self

    def __next__(self) -> ExactPublicationWindow:
        try:
            window = next(self._iterator)
        except StopIteration:
            self._exhausted = True
            raise
        if type(window) is not ExactPublicationWindow:
            raise ValueError("execution adapter windows must be exact publication windows")
        if window.index != self._expected_index:
            raise ValueError("publication-window indexes must be contiguous from zero")
        self._expected_index += 1
        phase = self._phase_ranges.get(window.phase)
        if phase is None:
            raise ValueError("publication window has an unknown accepted-group phase")
        if not (
            phase.start <= window.accepted_group_start < window.accepted_group_end <= phase.end
        ):
            raise ValueError("publication window accepted ordinals escape their phase range")
        if type(window.set_count) is not int or window.set_count < 0:
            raise ValueError("publication-window SET count must be nonnegative")
        if type(window.query_count) is not int or window.query_count < 0:
            raise ValueError("publication-window QUERY count must be nonnegative")
        stats = self._phase_stats[window.phase]
        stats["window_count"] += 1
        stats["set_count"] += window.set_count
        stats["query_count"] += window.query_count
        return window

    def finish(self) -> _CellAudit:
        if not self._exhausted:
            try:
                next(self)
            except StopIteration:
                pass
            else:
                raise ValueError("execution adapter did not consume the complete window stream")
        receipts: list[dict[str, object]] = []
        for phase_name in ("warmup", "tuning", "heldout"):
            phase = self._phase_ranges[phase_name]
            stats = self._phase_stats[phase_name]
            expected_query_count = _phase_query_count((phase.start, phase.end), self._rho)
            if stats["query_count"] != expected_query_count:
                raise ValueError("realized phase QUERY count does not match the exact RLE schedule")
            receipts.append(
                {
                    "phase": phase_name,
                    "accepted_event_group_range": [phase.start, phase.end],
                    "accepted_event_group_count": phase.end - phase.start,
                    "realized_publication_window_count": stats["window_count"],
                    "realized_set_count": stats["set_count"],
                    "realized_query_count": stats["query_count"],
                }
            )
        return _CellAudit(tuple(receipts))


def _digest(payload: object) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _require_sha256(value: object, field: str) -> str:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _require_git_sha(value: object, field: str) -> str:
    if type(value) is not str or _LOWER_GIT_SHA.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase 40-digit Git SHA")
    return value


def _fraction_text(value: Fraction) -> str:
    if value.denominator == 1:
        return str(value.numerator)
    denominator = value.denominator
    terminating = denominator
    while terminating % 2 == 0:
        terminating //= 2
    while terminating % 5 == 0:
        terminating //= 5
    if terminating != 1:
        return f"{value.numerator}/{value.denominator}"
    whole, remainder = divmod(value.numerator, value.denominator)
    digits: list[str] = []
    while remainder:
        remainder *= 10
        digit, remainder = divmod(remainder, value.denominator)
        digits.append(str(digit))
    return str(whole) if not digits else f"{whole}.{''.join(digits)}"


def _phase_query_count(accepted_range: tuple[int, int], rho: Fraction) -> int:
    start, end = accepted_range
    return (end * rho.numerator // rho.denominator) - (start * rho.numerator // rho.denominator)


def _validate_source_authority(source: _Day1BSourceAuthority) -> None:
    if type(source) is not _Day1BSourceAuthority:
        raise TypeError("source_authority must be an exact typed authority")
    _require_git_sha(source.git_sha, "experiment source Git SHA")
    if type(source.behavior_inventory) is not dict:
        raise ValueError("experiment source behavior inventory must be an exact object")
    inventory = source.behavior_inventory
    if (
        inventory.get("role") != EvidenceRole.DAY1B.value
        or inventory.get("source_git_sha") != source.git_sha
    ):
        raise ValueError("experiment source inventory must bind the DAY1B role and exact S1")
    _require_sha256(inventory.get("behavior_set_sha256"), "Behavior Set digest")
    if type(source.source_attestation) is not str or not source.source_attestation:
        raise ValueError("source authority attestation must be a nonempty string")


def _validate_trace(trace: _Day1BTraceInput) -> None:
    if type(trace) is not _Day1BTraceInput:
        raise TypeError("trace must be an exact typed Day1B trace input")
    if trace.dataset_id not in DATASET_IDS or trace.semantics not in SEMANTICS:
        raise ValueError("Day1B trace must name one frozen primary dataset and semantics")
    if type(trace.source_partition) is not int or trace.source_partition not in range(5):
        raise ValueError("Day1B source partition must be in [0, 5)")
    _require_git_sha(trace.trace_source_git_sha, "trace source Git SHA")
    for field in (
        "repository_provenance_sha256",
        "trace_manifest_sha256",
        "mapping_sha256",
        "accepted_events_sha256",
        "replay_receipt_sha256",
        "source_bundle_sha256",
        "query_vector_sha256",
    ):
        _require_sha256(getattr(trace, field), f"trace.{field}")
    for field in ("acquisition_transaction_sha256", "source_set_sha256"):
        value = getattr(trace, field)
        if value is not None:
            _require_sha256(value, f"trace.{field}")
    if type(trace.acquisition_network_authority_verified) is not bool:
        raise ValueError("trace acquisition authority must be one exact boolean")
    if type(trace.trace_source_authority_verified) is not bool:
        raise ValueError("trace source authority must be one exact boolean")
    if type(trace.accepted_group_count) is not int or trace.accepted_group_count < 10:
        raise ValueError("Day1B trace must contain at least ten accepted-event groups")
    if type(trace.query_vector) is not tuple or not trace.query_vector:
        raise ValueError("Day1B trace query vector must be one nonempty immutable vector")
    if any(type(value) is not int or value not in {-1, 0, 1} for value in trace.query_vector):
        raise ValueError("Day1B trace query vector must contain exact ternary integers")
    if type(trace.query_vector_canonical_bytes) is not bytes:
        raise ValueError("Day1B trace query vector must retain exact canonical bytes")
    if hashlib.sha256(trace.query_vector_canonical_bytes).hexdigest() != (
        trace.query_vector_sha256
    ):
        raise ValueError("Day1B trace query-vector bytes do not match their bound digest")
    try:
        query_vector_payload = json.loads(trace.query_vector_canonical_bytes.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Day1B trace query vector must be canonical ASCII JSON") from error
    if (
        type(query_vector_payload) is not dict
        or canonical_json_bytes(query_vector_payload) != trace.query_vector_canonical_bytes
        or query_vector_payload.get("schema_version") != QUERY_VECTOR_SCHEMA
        or query_vector_payload.get("values") != list(trace.query_vector)
    ):
        raise ValueError("Day1B trace query vector does not match its canonical artifact binding")


def _validate_catalog(catalog: Day1CandidateCatalog) -> tuple[RegisteredCandidate, ...]:
    if type(catalog) is not Day1CandidateCatalog:
        raise TypeError("candidate catalog must be an exact repository catalog")
    by_id = {candidate.candidate_id: candidate for candidate in catalog.candidates}
    if tuple(by_id) != FIXED_CANDIDATE_IDS or len(by_id) != len(FIXED_CANDIDATE_IDS):
        raise ValueError("candidate catalog must equal the analyzer's exact fixed roster order")
    if tuple(candidate.candidate_id for candidate in catalog.selection_candidates) != (
        REFERENCE_CANDIDATE_IDS
    ):
        raise ValueError("candidate catalog must equal the analyzer's 13-reference order")
    if tuple(candidate.candidate_id for candidate in catalog.ablation_candidates) != (
        ABLATION_CANDIDATE_ID,
    ):
        raise ValueError("candidate catalog must contain the exact one ablation")
    return catalog.candidates


def _expected_phase_ranges(total: int) -> tuple[AcceptedGroupPhaseRange, ...]:
    return (
        AcceptedGroupPhaseRange("warmup", 0, total // 10),
        AcceptedGroupPhaseRange("tuning", total // 10, total * 4 // 10),
        AcceptedGroupPhaseRange("heldout", total * 4 // 10, total),
    )


def _validate_program(
    program: _PublicationScheduleAdapter,
    *,
    trace: _Day1BTraceInput,
    rho: Fraction,
) -> None:
    if type(program) is not _PublicationScheduleAdapter:
        raise TypeError("schedule compiler must return an exact typed adapter")
    if program.schema_version != ACCEPTED_EVENT_SCHEDULE_SCHEMA:
        raise ValueError("Day1B rejects a non-v2 accepted-event schedule")
    if program.rho != rho or program.accepted_group_count != trace.accepted_group_count:
        raise ValueError("schedule adapter retargeted rho or accepted-event cardinality")
    if program.phase_ranges != _expected_phase_ranges(trace.accepted_group_count):
        raise ValueError("schedule adapter must preserve the exact 10/30/60 ordinal ranges")
    if type(program.total_set_count) is not int or program.total_set_count < 0:
        raise ValueError("schedule total SET count must be nonnegative")
    expected_queries = trace.accepted_group_count * rho.numerator // rho.denominator
    if program.total_query_count != expected_queries:
        raise ValueError("schedule total QUERY count does not match exact rational rho")
    _require_sha256(program.canonical_schedule_sha256, "canonical schedule digest")
    if not callable(program.iter_canonical_bytes) or not callable(program.stream_windows):
        raise TypeError("schedule adapter must provide streaming schedule/window callables")


def _trace_unit_document(
    trace: _Day1BTraceInput,
    source: _Day1BSourceAuthority,
) -> dict[str, object]:
    ranges = _expected_phase_ranges(trace.accepted_group_count)
    range_fields: dict[str, object] = {
        "accepted_raw_events_total": trace.accepted_group_count,
        "warmup_accepted_event_group_range": [ranges[0].start, ranges[0].end],
        "tuning_accepted_event_group_range": [ranges[1].start, ranges[1].end],
        "heldout_accepted_event_group_range": [ranges[2].start, ranges[2].end],
    }
    range_fields["accepted_event_group_ranges_sha256"] = _digest(range_fields)
    document: dict[str, object] = {
        "schema_version": TRACE_UNIT_SCHEMA,
        "experiment_source_git_sha": source.git_sha,
        "dataset_id": trace.dataset_id,
        "semantics": trace.semantics,
        "source_partition": trace.source_partition,
        "trace_manifest_sha256": trace.trace_manifest_sha256,
        "mapping_sha256": trace.mapping_sha256,
        "accepted_events_sha256": trace.accepted_events_sha256,
        **range_fields,
        "replay_receipt_sha256": trace.replay_receipt_sha256,
        "source_bundle_sha256": trace.source_bundle_sha256,
    }
    document["trace_binding_sha256"] = _digest(document)
    return document


def _cell_document(
    trace_unit: Mapping[str, object],
    trace: _Day1BTraceInput,
    source: _Day1BSourceAuthority,
    program: _PublicationScheduleAdapter,
    freshness: Fraction,
    audit: _CellAudit,
) -> dict[str, object]:
    rho_text = _fraction_text(program.rho)
    freshness_text = _fraction_text(freshness)
    phase_receipts = {str(receipt["phase"]): receipt for receipt in audit.phase_receipts}
    if set(phase_receipts) != {"warmup", "tuning", "heldout"}:
        raise ValueError("cell audit must contain the exact warmup/tuning/heldout phases")
    document: dict[str, object] = {
        "schema_version": CELL_BINDING_SCHEMA,
        "experiment_source_git_sha": source.git_sha,
        "dataset_id": trace.dataset_id,
        "semantics": trace.semantics,
        "source_partition": trace.source_partition,
        "freshness_seconds": freshness_text,
        "rho": rho_text,
        "trace_manifest_sha256": trace_unit["trace_manifest_sha256"],
        "mapping_sha256": trace_unit["mapping_sha256"],
        "accepted_events_sha256": trace_unit["accepted_events_sha256"],
        "accepted_raw_events_total": trace_unit["accepted_raw_events_total"],
        "warmup_accepted_event_group_range": trace_unit["warmup_accepted_event_group_range"],
        "tuning_accepted_event_group_range": trace_unit["tuning_accepted_event_group_range"],
        "heldout_accepted_event_group_range": trace_unit["heldout_accepted_event_group_range"],
        "accepted_event_group_ranges_sha256": trace_unit["accepted_event_group_ranges_sha256"],
        "replay_receipt_sha256": trace_unit["replay_receipt_sha256"],
        "source_bundle_sha256": trace_unit["source_bundle_sha256"],
        "trace_binding_sha256": trace_unit["trace_binding_sha256"],
        "tuning_update_count": phase_receipts["tuning"]["accepted_event_group_count"],
        "tuning_query_count": phase_receipts["tuning"]["realized_query_count"],
        "heldout_update_count": phase_receipts["heldout"]["accepted_event_group_count"],
        "heldout_query_count": phase_receipts["heldout"]["realized_query_count"],
        "event_schedule_schema_version": program.schema_version,
        "event_schedule_sha256": program.canonical_schedule_sha256,
        "query_vector_schema_version": QUERY_VECTOR_SCHEMA,
        "query_vector_sha256": trace.query_vector_sha256,
    }
    if (
        min(
            document["tuning_update_count"],
            document["tuning_query_count"],
            document["heldout_update_count"],
            document["heldout_query_count"],
        )
        <= 0
    ):
        raise ValueError("every Day1B tuning/held-out phase needs positive update/query counts")
    document["cell_binding_sha256"] = _digest(document)
    return document


def _primitive_count_document(value: tuple[int, ...] | None, field: str) -> dict[str, int]:
    if type(value) is not tuple or len(value) != len(PRIMITIVE_NAMES):
        raise ValueError(f"{field} must be the exact 14-primitive positional vector")
    if any(type(count) is not int or count < 0 for count in value):
        raise ValueError(f"{field} counts must be strict nonnegative integers")
    return dict(zip(PRIMITIVE_NAMES, value, strict=True))


def _serialized_ledger(
    categories: tuple[PublicationDay1BSerializedCategory, ...] | None,
    *,
    phase: str,
    candidate_id: str,
    cell_binding_sha256: str,
) -> tuple[dict[str, object], int, int]:
    if type(categories) is not tuple:
        raise ValueError("complete outcomes require the exact serialized-object category ledger")
    expected_categories = tuple(
        category for category, _transaction in SERIALIZED_PROTOCOL_OBJECT_CATEGORIES
    )
    if tuple(category.category for category in categories) != expected_categories:
        raise ValueError("serialized-object categories must be exact, complete, and canonical")
    rows: list[dict[str, object]] = []
    totals = {"update": 0, "query": 0, "one-time": 0}
    for category, (expected_name, transaction) in zip(
        categories,
        SERIALIZED_PROTOCOL_OBJECT_CATEGORIES,
        strict=True,
    ):
        if category.category != expected_name:
            raise ValueError("serialized-object category order changed")
        objects: list[dict[str, object]] = []
        category_bytes = 0
        category_objects = 0
        for ordinal, item in enumerate(category.objects):
            raw = item.serialized_bytes
            charged = len(raw) * item.multiplicity
            category_bytes += charged
            category_objects += item.multiplicity
            objects.append(
                {
                    "serialization_equivalence_class_ordinal": ordinal,
                    "serialized_byte_count": len(raw),
                    "serialized_sha256": hashlib.sha256(raw).hexdigest(),
                    "multiplicity": item.multiplicity,
                    "charged_byte_count": charged,
                }
            )
        totals[transaction] += category_bytes
        rows.append(
            {
                "category": expected_name,
                "transaction": transaction,
                "serialization_equivalence_class_count": len(objects),
                "protocol_object_count": category_objects,
                "charged_byte_count": category_bytes,
                "raw_serialized_objects": objects,
                "raw_serialized_object_digest_stream_sha256": _digest(objects),
            }
        )
    ledger: dict[str, object] = {
        "schema_version": DAY1B_SERIALIZATION_LEDGER_SCHEMA,
        "cell_binding_sha256": cell_binding_sha256,
        "phase": phase,
        "candidate_id": candidate_id,
        "byte_derivation": (
            "sum(actual-canonical-serialized-byte-length-times-exact-occurrence-multiplicity)"
        ),
        "ciphertext_count_used_as_byte_proxy": False,
        "categories": rows,
        "update_serialized_bytes": totals["update"],
        "query_serialized_bytes": totals["query"],
        "one_time_serialized_bytes_excluded_from_primary_C": totals["one-time"],
    }
    return ledger, totals["update"], totals["query"]


def _physical_record_and_ledger(
    measurement: PublicationDay1BMeasurement,
    *,
    trace: _Day1BTraceInput,
    cell: Mapping[str, object],
    phase: str,
    candidate_id: str,
    candidate_role: str,
    selection_source: str,
) -> tuple[dict[str, object], dict[str, object]]:
    if type(measurement) is not PublicationDay1BMeasurement:
        raise TypeError("execution adapter measurements must use the exact typed result")
    if measurement.outcome not in _OUTCOMES:
        raise ValueError("measurement outcome is outside the closed taxonomy")
    counts = (
        (cell["tuning_update_count"], cell["tuning_query_count"])
        if phase == "tuning-prefix"
        else (cell["heldout_update_count"], cell["heldout_query_count"])
    )
    if measurement.outcome == "complete":
        if measurement.failure_reason is not None:
            raise ValueError("complete outcomes must not carry a failure reason")
        update_counts = _primitive_count_document(
            measurement.update_primitive_counts,
            "update_primitive_counts",
        )
        query_counts = _primitive_count_document(
            measurement.query_primitive_counts,
            "query_primitive_counts",
        )
        ledger, update_bytes, query_bytes = _serialized_ledger(
            measurement.serialized_categories,
            phase=phase,
            candidate_id=candidate_id,
            cell_binding_sha256=str(cell["cell_binding_sha256"]),
        )
    else:
        if type(measurement.failure_reason) is not str or not measurement.failure_reason.strip():
            raise ValueError("incomplete outcomes require a nonempty failure reason")
        if any(
            value is not None
            for value in (
                measurement.update_primitive_counts,
                measurement.query_primitive_counts,
                measurement.serialized_categories,
            )
        ):
            raise ValueError("incomplete outcomes must discard all partial quantities")
        update_counts = None
        query_counts = None
        update_bytes = None
        query_bytes = None
        ledger = {
            "schema_version": DAY1B_SERIALIZATION_LEDGER_SCHEMA,
            "cell_binding_sha256": cell["cell_binding_sha256"],
            "phase": phase,
            "candidate_id": candidate_id,
            "byte_derivation": None,
            "ciphertext_count_used_as_byte_proxy": False,
            "categories": None,
            "update_serialized_bytes": None,
            "query_serialized_bytes": None,
            "one_time_serialized_bytes_excluded_from_primary_C": None,
        }
    record: dict[str, object] = {
        "schema_version": HELDOUT_RECORD_SCHEMA,
        "dataset_id": trace.dataset_id,
        "semantics": trace.semantics,
        "source_partition": trace.source_partition,
        "freshness_seconds": cell["freshness_seconds"],
        "rho": cell["rho"],
        "phase": phase,
        "record_kind": "fixed-candidate",
        "candidate_id": candidate_id,
        "candidate_role": candidate_role,
        "selection_source": selection_source,
        "cell_binding_sha256": cell["cell_binding_sha256"],
        "outcome": measurement.outcome,
        "failure_reason": measurement.failure_reason,
        "update_count": counts[0],
        "query_count": counts[1],
        "update_primitive_counts": update_counts,
        "query_primitive_counts": query_counts,
        "update_serialized_bytes": update_bytes,
        "query_serialized_bytes": query_bytes,
    }
    ledger["physical_record_sha256"] = _digest(record)
    ledger["serialization_ledger_sha256"] = _digest(ledger)
    return record, ledger


def _records_for_cell(
    result: PublicationDay1BCellMeasurements,
    *,
    trace: _Day1BTraceInput,
    cell: Mapping[str, object],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    if type(result) is not PublicationDay1BCellMeasurements:
        raise TypeError("execution adapter must return exact Day1B cell measurements")
    if type(result.tuning_references) is not tuple or len(result.tuning_references) != 13:
        raise ValueError("each cell must return exactly 13 tuning-reference executions")
    if type(result.heldout_fixed) is not tuple or len(result.heldout_fixed) != 14:
        raise ValueError("each cell must return exactly 14 held-out fixed executions")
    records: list[dict[str, object]] = []
    ledgers: list[dict[str, object]] = []
    for measurement, candidate_id in zip(
        result.tuning_references,
        REFERENCE_CANDIDATE_IDS,
        strict=True,
    ):
        record, ledger = _physical_record_and_ledger(
            measurement,
            trace=trace,
            cell=cell,
            phase="tuning-prefix",
            candidate_id=candidate_id,
            candidate_role="reference",
            selection_source="fixed-reference-tuning-prefix",
        )
        records.append(record)
        ledgers.append(ledger)
    for measurement, candidate_id in zip(
        result.heldout_fixed,
        FIXED_CANDIDATE_IDS,
        strict=True,
    ):
        is_ablation = candidate_id == ABLATION_CANDIDATE_ID
        record, ledger = _physical_record_and_ledger(
            measurement,
            trace=trace,
            cell=cell,
            phase="held-out",
            candidate_id=candidate_id,
            candidate_role="ablation" if is_ablation else "reference",
            selection_source=(
                "fixed-ablation-held-out" if is_ablation else "fixed-reference-held-out"
            ),
        )
        records.append(record)
        ledgers.append(ledger)
    return records, ledgers


def _validate_cell_resource_observations(
    result: PublicationDay1BCellMeasurements,
    resource_policy: PublicationDay1BResourcePolicy,
) -> None:
    if type(result.peak_resident_memory_bytes) is not int or (
        result.peak_resident_memory_bytes < 0
    ):
        raise ValueError(
            "cell peak resident-memory observation must be a strict nonnegative integer"
        )
    if type(result.peak_scratch_bytes) is not int or result.peak_scratch_bytes < 0:
        raise ValueError("cell peak scratch-byte observation must be a strict nonnegative integer")
    if result.peak_resident_memory_bytes > resource_policy.resident_memory_bytes:
        raise PublicationDay1BHold("Day1B cell exceeded the frozen resident-memory limit")
    if result.peak_scratch_bytes > resource_policy.scratch_bytes_per_cell:
        raise PublicationDay1BHold("Day1B cell exceeded the frozen scratch-byte limit")


def _write_new_file(path: Path, content: bytes) -> tuple[str, int]:
    with path.open("xb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    return hashlib.sha256(content).hexdigest(), len(content)


def _atomic_install(
    *,
    output_dir: Path,
    repository_root: Path,
    fragment: Mapping[str, object],
    ledgers: tuple[Mapping[str, object], ...],
    programs: tuple[_PublicationScheduleAdapter, ...],
    manifest_base: Mapping[str, object],
    resource_policy: PublicationDay1BResourcePolicy,
) -> PublicationDay1BUnitBundle:
    if output_dir.exists() or output_dir.is_symlink():
        raise ValueError("output_dir must be a new path")
    resolved_repository = repository_root.resolve()
    resolved_output = output_dir.resolve(strict=False)
    if resolved_output == resolved_repository or resolved_output.is_relative_to(
        resolved_repository
    ):
        raise ValueError("output_dir must be outside the source checkout")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{output_dir.name}.publication-day1b-staging-",
            dir=output_dir.parent,
        )
    )
    lock_path = output_dir.with_name(f".{output_dir.name}.publication-day1b.lock")
    lock_fd: int | None = None
    try:
        fragment_bytes = canonical_json_bytes(fragment)
        fragment_sha, fragment_size = _write_new_file(
            staging / _FRAGMENT_FILENAME,
            fragment_bytes,
        )
        ledger_bytes = b"".join(canonical_json_bytes(ledger) for ledger in ledgers)
        ledger_sha, ledger_size = _write_new_file(staging / _LEDGER_FILENAME, ledger_bytes)

        schedule_hasher = hashlib.sha256()
        schedule_size = 0
        schedule_index: list[dict[str, object]] = []
        with (staging / _SCHEDULE_FILENAME).open("xb") as handle:
            for program in programs:
                program_hasher = hashlib.sha256()
                line_count = 0
                byte_count = 0
                for chunk in program.iter_canonical_bytes():
                    if type(chunk) is not bytes or not chunk.endswith(b"\n"):
                        raise ValueError(
                            "schedule chunks must be canonical newline-terminated bytes"
                        )
                    handle.write(chunk)
                    schedule_hasher.update(chunk)
                    program_hasher.update(chunk)
                    line_count += 1
                    byte_count += len(chunk)
                if program_hasher.hexdigest() != program.canonical_schedule_sha256:
                    raise ValueError("schedule bytes do not match canonical_schedule_sha256")
                if line_count != program.accepted_group_count + 1:
                    raise ValueError("RLE schedule must contain one header plus one group record")
                schedule_size += byte_count
                schedule_index.append(
                    {
                        "rho": _fraction_text(program.rho),
                        "schema_version": program.schema_version,
                        "canonical_schedule_sha256": program.canonical_schedule_sha256,
                        "jsonl_line_count": line_count,
                        "byte_count": byte_count,
                        "query_events_materialized": False,
                    }
                )
            handle.flush()
            os.fsync(handle.fileno())
        schedule_sha = schedule_hasher.hexdigest()

        members = {
            _FRAGMENT_FILENAME: {"sha256": fragment_sha, "byte_count": fragment_size},
            _SCHEDULE_FILENAME: {"sha256": schedule_sha, "byte_count": schedule_size},
            _LEDGER_FILENAME: {"sha256": ledger_sha, "byte_count": ledger_size},
        }
        manifest = {
            **manifest_base,
            "schedule_index": schedule_index,
            "members": members,
            "heldout_input_member_sha256": fragment_sha,
        }
        manifest_bytes = canonical_json_bytes(manifest)
        manifest_sha, manifest_size = _write_new_file(
            staging / _MANIFEST_FILENAME,
            manifest_bytes,
        )
        member_bytes = {
            _MANIFEST_FILENAME: (manifest_sha, manifest_size),
            _FRAGMENT_FILENAME: (fragment_sha, fragment_size),
            _SCHEDULE_FILENAME: (schedule_sha, schedule_size),
            _LEDGER_FILENAME: (ledger_sha, ledger_size),
        }
        checksum_bytes = "".join(
            f"{member_bytes[name][0]}  {name}\n" for name in _CHECKSUM_TARGETS
        ).encode("ascii")
        checksums_sha, checksums_size = _write_new_file(
            staging / _CHECKSUM_FILENAME,
            checksum_bytes,
        )
        total_output_bytes = sum(size for _digest_value, size in member_bytes.values()) + (
            checksums_size
        )
        if total_output_bytes > resource_policy.output_bytes_per_unit:
            raise PublicationDay1BHold("Day1B unit exceeded the frozen output-byte limit")
        actual_names = {entry.name for entry in staging.iterdir()}
        if actual_names != set(_ARTIFACT_FILENAMES):
            raise RuntimeError("internal Day1B staging tree is not closed")
        lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        if output_dir.exists() or output_dir.is_symlink():
            raise ValueError("output_dir was claimed concurrently")
        os.rename(staging, output_dir)
        return PublicationDay1BUnitBundle(
            output_dir=output_dir,
            manifest_path=output_dir / _MANIFEST_FILENAME,
            heldout_fragment_path=output_dir / _FRAGMENT_FILENAME,
            schedule_path=output_dir / _SCHEDULE_FILENAME,
            serialization_ledger_path=output_dir / _LEDGER_FILENAME,
            checksums_path=output_dir / _CHECKSUM_FILENAME,
            manifest_sha256=manifest_sha,
            heldout_fragment_sha256=fragment_sha,
            schedule_sha256=schedule_sha,
            serialization_ledger_sha256=ledger_sha,
            checksums_sha256=checksums_sha,
        )
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
            lock_path.unlink(missing_ok=True)
        shutil.rmtree(staging, ignore_errors=True)


def _produce_publication_day1b_unit(
    *,
    trace: _Day1BTraceInput,
    output_dir: Path,
    source_authority: _Day1BSourceAuthority,
    candidate_catalog: Day1CandidateCatalog,
    resource_policy: PublicationDay1BResourcePolicy,
    execution_adapter: _Day1BExecutionAdapter,
    repository_root: Path,
) -> PublicationDay1BUnitBundle:
    """Build one complete unit through typed internal seams and one-pass windows."""

    if not isinstance(output_dir, Path) or not isinstance(repository_root, Path):
        raise TypeError("output_dir and repository_root must be pathlib.Path values")
    if output_dir.exists() or output_dir.is_symlink():
        raise ValueError("output_dir must be a new path")
    _validate_trace(trace)
    _validate_source_authority(source_authority)
    candidates = _validate_catalog(candidate_catalog)
    if type(resource_policy) is not PublicationDay1BResourcePolicy:
        raise TypeError("resource_policy must be an exact fixed policy")
    if not callable(getattr(execution_adapter, "execute_cell", None)):
        raise TypeError("execution_adapter must provide the typed streaming cell seam")

    programs = tuple(trace.compile_schedule(Fraction(rho)) for rho in RHO_VALUES)
    for program, rho in zip(programs, (Fraction(value) for value in RHO_VALUES), strict=True):
        _validate_program(program, trace=trace, rho=rho)

    trace_unit = _trace_unit_document(trace, source_authority)
    cells: list[dict[str, object]] = []
    records: list[dict[str, object]] = []
    ledgers: list[dict[str, object]] = []
    cell_execution_receipts: list[dict[str, object]] = []
    for freshness_text in FRESHNESS_VALUES:
        freshness = Fraction(freshness_text)
        for program in programs:
            audited_windows = _AuditedWindowStream(
                program.stream_windows(freshness),
                program.phase_ranges,
                program.rho,
            )
            start = time.monotonic()
            result = execution_adapter.execute_cell(
                windows=audited_windows,
                trace=trace,
                freshness=freshness,
                rho=program.rho,
                candidates=candidates,
                query_vector=trace.query_vector,
                resource_policy=resource_policy,
            )
            elapsed = time.monotonic() - start
            if elapsed > resource_policy.wall_clock_seconds_per_cell:
                raise PublicationDay1BHold("Day1B cell exceeded the frozen wall-clock limit")
            if type(result) is not PublicationDay1BCellMeasurements:
                raise TypeError("execution adapter must return exact Day1B cell measurements")
            _validate_cell_resource_observations(result, resource_policy)
            audit = audited_windows.finish()
            cell = _cell_document(
                trace_unit,
                trace,
                source_authority,
                program,
                freshness,
                audit,
            )
            cell_records, cell_ledgers = _records_for_cell(
                result,
                trace=trace,
                cell=cell,
            )
            cells.append(cell)
            records.extend(cell_records)
            ledgers.extend(cell_ledgers)
            cell_execution_receipts.append(
                {
                    "cell_binding_sha256": cell["cell_binding_sha256"],
                    "freshness_seconds": cell["freshness_seconds"],
                    "rho": cell["rho"],
                    "phase_receipts": list(audit.phase_receipts),
                    "physical_record_count": len(cell_records),
                    "candidate_retry_count": 0,
                    "peak_resident_memory_bytes": result.peak_resident_memory_bytes,
                    "peak_scratch_bytes": result.peak_scratch_bytes,
                }
            )
    if (len(cells), len(records), len(ledgers)) != (18, 486, 486):
        raise RuntimeError("Day1B unit cardinality did not close at 18/486/486")

    fragment = {
        "schema_version": DAY1B_UNIT_FRAGMENT_SCHEMA,
        "experiment_source_git_sha": source_authority.git_sha,
        "trace_units": [trace_unit],
        "cell_bindings": cells,
        "records": records,
    }
    registration = asdict(candidate_catalog.registration)
    catalog_document = {
        "registration": registration,
        "registration_sha256": _digest(registration),
        "fixed_candidate_ids": list(FIXED_CANDIDATE_IDS),
        "reference_candidate_ids": list(REFERENCE_CANDIDATE_IDS),
        "ablation_candidate_ids": [ABLATION_CANDIDATE_ID],
    }
    resource_document = resource_policy.to_document()
    manifest_base = {
        "schema_version": DAY1B_UNIT_SCHEMA,
        "artifact_policy": "derived-publication-evidence-no-raw-source-redistribution",
        "unit_identity": {
            "dataset_id": trace.dataset_id,
            "dataset_release": trace.dataset_release,
            "semantics": trace.semantics,
            "source_partition": trace.source_partition,
        },
        "experiment_source": {
            "git_sha": source_authority.git_sha,
            "source_attestation": source_authority.source_attestation,
            "behavior_inventory": dict(source_authority.behavior_inventory),
        },
        "trace_source": {
            "git_sha": trace.trace_source_git_sha,
            "repository_provenance_sha256": trace.repository_provenance_sha256,
            "trace_manifest_sha256": trace.trace_manifest_sha256,
            "trace_source_authority_verified": trace.trace_source_authority_verified,
        },
        "acquisition_binding": {
            "acquisition_transaction_sha256": trace.acquisition_transaction_sha256,
            "source_set_sha256": trace.source_set_sha256,
            "source_bundle_sha256": trace.source_bundle_sha256,
            "acquisition_network_authority_verified": (
                trace.acquisition_network_authority_verified
            ),
        },
        "query_vector": {
            "schema_version": QUERY_VECTOR_SCHEMA,
            "sha256": trace.query_vector_sha256,
            "reuse_scope": "one-paired-unit-all-18-cells-and-all-physical-candidates",
        },
        "candidate_catalog": catalog_document,
        "resource_policy": resource_document,
        "invocation": {
            "entrypoint": "scripts/run_publication_day1b.py",
            "public_interface": (
                "produce_publication_day1b_unit(trace_bundle_dir:Path,output_dir:Path)"
            ),
            "caller_options_allowed": False,
            "shard_scope": "exactly-one-paired-unit-18-cells",
            "selective_candidate_retry_allowed": False,
        },
        "cardinality": {
            "cell_binding_count": 18,
            "physical_record_count": 486,
            "schedule_program_count": 9,
            "serialization_ledger_count": 486,
        },
        "cell_execution_receipts": cell_execution_receipts,
        "authority": {
            "local_integrity_verified": True,
            "schedule_v2_verified": True,
            "serialized_protocol_object_bytes_verified": True,
            "derived_aliases_materialized": False,
            "day1b_behavior_source_verified": (
                source_authority.source_attestation == "repository-clean-head"
            ),
            "trace_source_authority_verified": trace.trace_source_authority_verified,
            "acquisition_network_authority_verified": (
                trace.acquisition_network_authority_verified
            ),
            "runtime_execution_isolation_verified": False,
            "publication_claim_allowed": False,
        },
    }
    return _atomic_install(
        output_dir=output_dir,
        repository_root=repository_root,
        fragment=fragment,
        ledgers=tuple(ledgers),
        programs=programs,
        manifest_base=manifest_base,
        resource_policy=resource_policy,
    )


def _produce_publication_day1b_unit_for_test(
    *,
    trace: _Day1BTraceInput,
    output_dir: Path,
    source_authority: _Day1BSourceAuthority,
    candidate_catalog: Day1CandidateCatalog,
    resource_policy: PublicationDay1BResourcePolicy,
    execution_adapter: _Day1BExecutionAdapter,
) -> PublicationDay1BUnitBundle:
    """Private typed small-fixture seam; its artifacts have no publication authority."""

    current_test = os.environ.get("PYTEST_CURRENT_TEST", "")
    if not current_test.startswith("tests/test_publication_day1b.py::"):
        raise RuntimeError("the private Day1B fixture seam is unavailable to production callers")
    return _produce_publication_day1b_unit(
        trace=trace,
        output_dir=output_dir,
        source_authority=source_authority,
        candidate_catalog=candidate_catalog,
        resource_policy=resource_policy,
        execution_adapter=execution_adapter,
        repository_root=Path(__file__).resolve().parents[2],
    )


def _repository_day1b_resource_policy() -> PublicationDay1BResourcePolicy:
    raise PublicationDay1BHold(
        "HOLD: publication Day1B resource policy is still PENDING-FREEZE after the "
        "outcome-blind structure pilot"
    )


def _repository_day1b_execution_adapter() -> _Day1BExecutionAdapter:
    raise PublicationDay1BHold(
        "HOLD: no repository-owned streaming Day1B serialization/execution producer is installed"
    )


def _read_regular_file(path: Path, field: str) -> bytes:
    if path.is_symlink():
        raise ValueError(f"{field} must not be a symbolic link")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"{field} must be an existing regular file") from error
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError(f"{field} must be an existing regular file")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _repository_program_adapter(program: AcceptedGroupProgram) -> _PublicationScheduleAdapter:
    return _PublicationScheduleAdapter(
        schema_version=program.schema_version,
        rho=program.rho,
        phase_ranges=program.phase_ranges,
        accepted_group_count=program.accepted_group_count,
        total_set_count=program.total_set_count,
        total_query_count=program.total_query_count,
        canonical_schedule_sha256=program.canonical_schedule_sha256,
        iter_canonical_bytes=program.iter_canonical_bytes,
        stream_windows=lambda freshness: stream_publication_windows(program, freshness),
    )


def _validated_trace_v6_acquisition_binding(
    manifest: dict[str, object],
) -> dict[str, object]:
    binding = manifest.get("acquisition_binding")
    if type(binding) is not dict:
        raise ValueError("trace-v6 acquisition_binding must be an exact object")
    if binding.get("schema_version") != ACQUISITION_TRACE_BINDING_SCHEMA:
        raise ValueError("trace-v6 acquisition_binding schema is not frozen")
    if binding.get("dataset_id") != manifest.get("dataset_id") or binding.get(
        "dataset_release"
    ) != manifest.get("dataset_release"):
        raise ValueError("trace-v6 acquisition_binding dataset identity does not match")
    _require_sha256(
        binding.get("acquisition_transaction_sha256"),
        "trace-v6 acquisition transaction",
    )
    _require_sha256(binding.get("source_set_sha256"), "trace-v6 source set")

    authority = binding.get("authority")
    expected_authority_keys = {
        "state",
        "formal_authority_granted",
        "acquisition_network_authority_verified",
        "post_run_anchor_verified",
        "evidence_compatibility_verified",
        "claims_authorized",
    }
    if type(authority) is not dict or set(authority) != expected_authority_keys:
        raise ValueError("trace-v6 acquisition authority must be one closed object")
    state = authority["state"]
    false_fields = expected_authority_keys - {"state"}
    if (
        type(state) is not str
        or not state.startswith("HOLD-")
        or any(authority[field] is not False for field in false_fields)
    ):
        raise ValueError("trace-v6 acquisition authority must remain HOLD/false")
    return binding


def _load_repository_trace_input(trace_bundle_dir: Path) -> _Day1BTraceInput:
    manifest_path = trace_bundle_dir / "publication-trace-manifest.json"
    query_vector_path = trace_bundle_dir / "publication-query-vector.json"
    manifest_before = _read_regular_file(manifest_path, "publication trace manifest")
    query_vector_before = _read_regular_file(query_vector_path, "publication query vector")
    try:
        manifest = json.loads(manifest_before.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("publication trace manifest must be canonical ASCII JSON") from error
    if type(manifest) is not dict or canonical_json_bytes(manifest) != manifest_before:
        raise ValueError("publication trace manifest must be canonical closed JSON")
    validated: ValidatedPublicationTrace = load_publication_trace_bundle(trace_bundle_dir)
    manifest_after = _read_regular_file(manifest_path, "publication trace manifest")
    query_vector_after = _read_regular_file(query_vector_path, "publication query vector")
    if manifest_after != manifest_before or hashlib.sha256(manifest_after).hexdigest() != (
        validated.manifest_sha256
    ):
        raise ValueError("publication trace manifest changed during Day1B validation")
    if (
        query_vector_after != query_vector_before
        or hashlib.sha256(query_vector_after).hexdigest() != validated.query_vector_sha256
    ):
        raise ValueError("publication query vector changed during Day1B validation")
    provenance = manifest["repository_provenance"]
    acquisition_binding = _validated_trace_v6_acquisition_binding(manifest)
    replay_receipt = {
        "schema_version": DAY1B_REPLAY_RECEIPT_SCHEMA,
        "trace_manifest_sha256": validated.manifest_sha256,
        "trace_jsonl_sha256": validated.trace_jsonl_sha256,
        "repository_provenance_sha256": validated.repository_provenance_sha256,
        "accepted_group_count": validated.accepted_group_count,
        "transition_count": validated.transition_count,
        "replayed_by_closed_schedule_loader": True,
    }

    def compile_schedule(rho: Fraction) -> _PublicationScheduleAdapter:
        return _repository_program_adapter(compile_accepted_group_program(validated, rho))

    return _Day1BTraceInput(
        dataset_id=validated.dataset_id,
        dataset_release=validated.dataset_release,
        semantics=validated.semantics,
        source_partition=validated.source_partition,
        trace_source_git_sha=str(provenance["source_git_sha"]),
        repository_provenance_sha256=validated.repository_provenance_sha256,
        trace_manifest_sha256=validated.manifest_sha256,
        mapping_sha256=validated.mapping_sha256,
        accepted_events_sha256=str(manifest["accepted_raw_event_sha256"]),
        replay_receipt_sha256=_digest(replay_receipt),
        source_bundle_sha256=_digest(acquisition_binding),
        acquisition_transaction_sha256=str(acquisition_binding["acquisition_transaction_sha256"]),
        source_set_sha256=str(acquisition_binding["source_set_sha256"]),
        acquisition_network_authority_verified=False,
        accepted_group_count=validated.accepted_group_count,
        query_vector=validated.query_vector,
        query_vector_canonical_bytes=query_vector_after,
        query_vector_sha256=validated.query_vector_sha256,
        compile_schedule=compile_schedule,
        trace_source_authority_verified=False,
    )


def produce_publication_day1b_unit(
    trace_bundle_dir: Path,
    output_dir: Path,
) -> PublicationDay1BUnitBundle:
    """Produce one exact Day1B unit, or fail before creating output.

    The caller cannot supply candidates, schedules, ratios, freshness, source claims,
    serialization facts, or resource options. All production dependencies are obtained from
    zero-argument repository seams before the trace is executed.
    """

    if not isinstance(trace_bundle_dir, Path) or not isinstance(output_dir, Path):
        raise TypeError("trace_bundle_dir and output_dir must be pathlib.Path values")
    if output_dir.exists() or output_dir.is_symlink():
        raise ValueError("output_dir must be a new path")
    repository_root = Path(__file__).resolve().parents[2]
    try:
        source_attestation = verify_current_role_source(EvidenceRole.DAY1B, repository_root)
        behavior_inventory = capture_behavior_inventory(
            EvidenceRole.DAY1B,
            source_git_sha=source_attestation.git_sha,
            repository_root=repository_root,
        )
    except EvidenceCompatibilityError as error:
        raise PublicationDay1BHold(
            f"HOLD: DAY1B Behavior Set/source authority is unavailable: {error}"
        ) from error
    source_authority = _Day1BSourceAuthority(
        git_sha=source_attestation.git_sha,
        behavior_inventory=behavior_inventory,
        source_attestation=source_attestation.attestation,
    )
    try:
        catalog = repository_day1_candidate_catalog()
    except Day1CandidateRegistrationError as error:
        raise PublicationDay1BHold(
            f"HOLD: complete Day1B candidate catalog unavailable: {error}"
        ) from error
    resource_policy = _repository_day1b_resource_policy()
    execution_adapter = _repository_day1b_execution_adapter()
    trace = _load_repository_trace_input(trace_bundle_dir)
    if not trace.trace_source_authority_verified:
        raise PublicationDay1BHold(
            "HOLD: trace acquisition/evidence compatibility authority is not installed"
        )
    return _produce_publication_day1b_unit(
        trace=trace,
        output_dir=output_dir,
        source_authority=source_authority,
        candidate_catalog=catalog,
        resource_policy=resource_policy,
        execution_adapter=execution_adapter,
        repository_root=repository_root,
    )


__all__ = (
    "DAY1B_RESOURCE_POLICY_SCHEMA",
    "DAY1B_SERIALIZATION_LEDGER_SCHEMA",
    "DAY1B_UNIT_FRAGMENT_SCHEMA",
    "DAY1B_UNIT_SCHEMA",
    "SERIALIZED_PROTOCOL_OBJECT_CATEGORIES",
    "PublicationDay1BCellMeasurements",
    "PublicationDay1BHold",
    "PublicationDay1BMeasurement",
    "PublicationDay1BResourcePolicy",
    "PublicationDay1BSerializedCategory",
    "PublicationDay1BSerializedObject",
    "PublicationDay1BUnitBundle",
    "produce_publication_day1b_unit",
)
