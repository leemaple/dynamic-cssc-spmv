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
import sqlite3
import stat
import tempfile
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import suppress
from dataclasses import asdict, dataclass
from fractions import Fraction
from pathlib import Path
from typing import BinaryIO, Protocol

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
from dynamic_cssc.publication_day1b_worker_protocol import (
    DAY1B_WORKER_REQUIRED_F1M_BINDING_CATEGORIES,
    Day1BClaimedWorkerEvidence,
    Day1BWorkerCandidateSpec,
    Day1BWorkerCellReceipt,
    Day1BWorkerInvocationCapability,
    Day1BWorkerPhaseAudit,
    Day1BWorkerPhaseRange,
    Day1BWorkerPhaseReceipt,
    Day1BWorkerProtocolContract,
    Day1BWorkerProtocolError,
    Day1BWorkerResourceLimits,
    Day1BWorkerSerializedCategoryReceipt,
    abandon_day1b_worker_invocation,
    canonical_day1b_worker_window_audit_bytes,
    claim_day1b_worker_evidence,
    consume_day1b_worker_frames,
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
_OBJECT_RECEIPT_FILENAME = "serialized-object-receipts.jsonl"
_CHECKSUM_FILENAME = "SHA256SUMS"
_ARTIFACT_FILENAMES = (
    _MANIFEST_FILENAME,
    _FRAGMENT_FILENAME,
    _SCHEDULE_FILENAME,
    _LEDGER_FILENAME,
    _OBJECT_RECEIPT_FILENAME,
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

    wall_clock_seconds_per_candidate_cell: int
    resident_memory_bytes_per_candidate_cell: int
    scratch_bytes_per_candidate_cell: int
    serialized_object_bytes_maximum: int
    serialized_object_receipt_count_maximum: int
    serialized_object_receipt_spool_bytes_maximum: int
    serialized_payload_bytes_per_cell_maximum: int
    worker_frame_count_maximum: int
    controller_registered_scratch_bytes_checkpoint_maximum: int
    output_bytes_per_unit: int
    cells_per_shard: int
    max_concurrency: int
    candidate_retry_count: int
    infrastructure_preemption_whole_shard_rerun_limit: int
    authority: str

    def __post_init__(self) -> None:
        for field in (
            "wall_clock_seconds_per_candidate_cell",
            "resident_memory_bytes_per_candidate_cell",
            "scratch_bytes_per_candidate_cell",
            "serialized_object_bytes_maximum",
            "serialized_object_receipt_count_maximum",
            "serialized_object_receipt_spool_bytes_maximum",
            "serialized_payload_bytes_per_cell_maximum",
            "worker_frame_count_maximum",
            "controller_registered_scratch_bytes_checkpoint_maximum",
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
                self.wall_clock_seconds_per_candidate_cell,
                self.resident_memory_bytes_per_candidate_cell,
                self.scratch_bytes_per_candidate_cell,
                self.serialized_object_bytes_maximum,
                self.serialized_object_receipt_count_maximum,
                self.serialized_object_receipt_spool_bytes_maximum,
                self.serialized_payload_bytes_per_cell_maximum,
                self.worker_frame_count_maximum,
                self.controller_registered_scratch_bytes_checkpoint_maximum,
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

    def to_worker_limits(self) -> Day1BWorkerResourceLimits:
        return Day1BWorkerResourceLimits(
            wall_clock_ns_per_candidate_cell=(
                self.wall_clock_seconds_per_candidate_cell * 1_000_000_000
            ),
            resident_memory_bytes_per_candidate_cell=(
                self.resident_memory_bytes_per_candidate_cell
            ),
            scratch_bytes_per_candidate_cell=self.scratch_bytes_per_candidate_cell,
            serialized_object_bytes_maximum=self.serialized_object_bytes_maximum,
            serialized_object_receipt_count_maximum=(self.serialized_object_receipt_count_maximum),
            serialized_object_receipt_spool_bytes_maximum=(
                self.serialized_object_receipt_spool_bytes_maximum
            ),
            serialized_payload_bytes_per_cell_maximum=(
                self.serialized_payload_bytes_per_cell_maximum
            ),
            worker_frame_count_maximum=self.worker_frame_count_maximum,
            controller_registered_scratch_bytes_checkpoint_maximum=(
                self.controller_registered_scratch_bytes_checkpoint_maximum
            ),
        )


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
    """Launch exactly one canonical candidate×cell worker invocation.

    The adapter owns every minted invocation capability until an exact
    :class:`_Day1BWorkerLaunch` returns. It must abandon that capability on every
    pre-return exception; after return, ownership transfers to the core.
    """

    def execute_candidate_cell(
        self,
        *,
        windows: Iterator[ExactPublicationWindow],
        contract_seed: _Day1BWorkerContractSeed,
    ) -> _Day1BWorkerLaunch: ...


@dataclass(frozen=True, slots=True)
class _Day1BWorkerLaunch:
    """Controller output for one candidate×cell; never a caller-minted receipt."""

    contract: Day1BWorkerProtocolContract
    frame_chunks: Iterable[bytes]
    invocation_capability: Day1BWorkerInvocationCapability

    def __post_init__(self) -> None:
        if type(self.contract) is not Day1BWorkerProtocolContract:
            raise TypeError("worker launch requires one exact bound contract")
        if type(self.invocation_capability) is not Day1BWorkerInvocationCapability:
            raise TypeError("worker launch requires one exact invocation capability")
        try:
            iter(self.frame_chunks)
        except TypeError as error:
            raise TypeError("worker launch frame chunks must be iterable") from error


@dataclass(frozen=True, slots=True)
class PublicationDay1BUnitBundle:
    """Paths and independently recomputed member identities of one installed unit."""

    output_dir: Path
    manifest_path: Path
    heldout_fragment_path: Path
    schedule_path: Path
    serialization_ledger_path: Path
    serialized_object_receipt_path: Path
    checksums_path: Path
    manifest_sha256: str
    heldout_fragment_sha256: str
    schedule_sha256: str
    serialization_ledger_sha256: str
    serialized_object_receipt_sha256: str
    checksums_sha256: str


@dataclass(frozen=True, slots=True)
class _CellAudit:
    phase_audits: tuple[Day1BWorkerPhaseAudit, ...]

    @property
    def phase_receipts(self) -> tuple[dict[str, object], ...]:
        return tuple(
            {
                "phase": audit.phase,
                "accepted_event_group_range": [
                    audit.accepted_group_start,
                    audit.accepted_group_end,
                ],
                "accepted_event_group_count": (
                    audit.accepted_group_end - audit.accepted_group_start
                ),
                "realized_publication_window_count": audit.realized_window_count,
                "realized_set_count": audit.realized_set_count,
                "realized_query_count": audit.realized_query_count,
                "consumed_window_audit_stream_sha256": (audit.consumed_window_audit_stream_sha256),
            }
            for audit in self.phase_audits
        )


class _AuditedWindowStream:
    """Audit a one-pass schedule stream without retaining Publication Windows."""

    __slots__ = (
        "_expected_index",
        "_exhausted",
        "_iterator",
        "_phase_hashers",
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
        self._phase_hashers = {phase.name: hashlib.sha256() for phase in phase_ranges}
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
        self._phase_hashers[window.phase].update(
            canonical_day1b_worker_window_audit_bytes(
                index=window.index,
                phase=window.phase,
                accepted_group_start=window.accepted_group_start,
                accepted_group_end=window.accepted_group_end,
                start_time=window.start_time,
                end_time=window.end_time,
                set_count=window.set_count,
                updates=tuple(
                    (update.row, update.col, update.before, update.after)
                    for update in window.updates
                ),
                query_count=window.query_count,
                reason=window.reason,
            )
        )
        return window

    def finish(self) -> _CellAudit:
        if not self._exhausted:
            try:
                next(self)
            except StopIteration:
                pass
            else:
                raise ValueError("execution adapter did not consume the complete window stream")
        receipts: list[Day1BWorkerPhaseAudit] = []
        for phase_name in ("warmup", "tuning", "heldout"):
            phase = self._phase_ranges[phase_name]
            stats = self._phase_stats[phase_name]
            expected_query_count = _phase_query_count((phase.start, phase.end), self._rho)
            if stats["query_count"] != expected_query_count:
                raise ValueError("realized phase QUERY count does not match the exact RLE schedule")
            receipts.append(
                Day1BWorkerPhaseAudit(
                    phase=phase_name,
                    accepted_group_start=phase.start,
                    accepted_group_end=phase.end,
                    realized_window_count=stats["window_count"],
                    realized_set_count=stats["set_count"],
                    realized_query_count=stats["query_count"],
                    consumed_window_audit_stream_sha256=(
                        self._phase_hashers[phase_name].hexdigest()
                    ),
                )
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
    categories: tuple[Day1BWorkerSerializedCategoryReceipt, ...] | None,
    *,
    phase: str,
    candidate_id: str,
    cell_binding_sha256: str,
    worker_object_receipt_spool_sha256: str,
) -> tuple[dict[str, object], int, int]:
    if type(categories) is not tuple:
        raise ValueError("complete outcomes require the exact serialized-object category ledger")
    expected_categories = tuple(
        category for category, _transaction in SERIALIZED_PROTOCOL_OBJECT_CATEGORIES
    )
    if tuple(category.category for category in categories) != expected_categories:
        raise ValueError("serialized-object categories must be exact, complete, and canonical")
    _require_sha256(
        worker_object_receipt_spool_sha256,
        "worker object-receipt spool digest",
    )
    rows: list[dict[str, object]] = []
    totals = {"update": 0, "query": 0, "one-time": 0}
    for category, (expected_name, transaction) in zip(
        categories,
        SERIALIZED_PROTOCOL_OBJECT_CATEGORIES,
        strict=True,
    ):
        if (
            type(category) is not Day1BWorkerSerializedCategoryReceipt
            or category.category != expected_name
            or category.transaction != transaction
        ):
            raise ValueError("serialized-object category order changed")
        totals[transaction] += category.charged_byte_count
        rows.append(category.to_document())
    ledger: dict[str, object] = {
        "schema_version": DAY1B_SERIALIZATION_LEDGER_SCHEMA,
        "cell_binding_sha256": cell_binding_sha256,
        "phase": phase,
        "candidate_id": candidate_id,
        "byte_derivation": (
            "worker-streamed-canonical-byte-length-times-exact-occurrence-multiplicity"
        ),
        "ciphertext_count_used_as_byte_proxy": False,
        "raw_serialized_protocol_bytes_retained": False,
        "worker_object_receipt_spool_sha256": (worker_object_receipt_spool_sha256),
        "categories": rows,
        "update_serialized_bytes": totals["update"],
        "query_serialized_bytes": totals["query"],
        "one_time_serialized_bytes_excluded_from_primary_C": totals["one-time"],
    }
    return ledger, totals["update"], totals["query"]


def _physical_record_and_ledger(
    measurement: Day1BWorkerPhaseReceipt,
    *,
    trace: _Day1BTraceInput,
    cell: Mapping[str, object],
    phase: str,
    candidate_id: str,
    candidate_role: str,
    selection_source: str,
    worker_object_receipt_spool_sha256: str,
) -> tuple[dict[str, object], dict[str, object]]:
    if type(measurement) is not Day1BWorkerPhaseReceipt:
        raise TypeError("execution adapter measurements must use the exact typed result")
    _require_sha256(
        worker_object_receipt_spool_sha256,
        "worker object-receipt spool digest",
    )
    if measurement.outcome not in _OUTCOMES:
        raise ValueError("measurement outcome is outside the closed taxonomy")
    counts = (
        (cell["tuning_update_count"], cell["tuning_query_count"])
        if phase == "tuning-prefix"
        else (cell["heldout_update_count"], cell["heldout_query_count"])
    )
    if measurement.outcome == "complete":
        if measurement.failure_code is not None:
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
            worker_object_receipt_spool_sha256=(worker_object_receipt_spool_sha256),
        )
    else:
        if type(measurement.failure_code) is not str or not measurement.failure_code.strip():
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
            "raw_serialized_protocol_bytes_retained": False,
            "worker_object_receipt_spool_sha256": (worker_object_receipt_spool_sha256),
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
        "failure_reason": measurement.failure_code,
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


def _records_for_candidate_cell(
    result: Day1BWorkerCellReceipt,
    *,
    trace: _Day1BTraceInput,
    cell: Mapping[str, object],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    if type(result) is not Day1BWorkerCellReceipt:
        raise TypeError("decoder must return exact candidate-cell evidence")
    candidate = result.candidate
    if candidate.candidate_id not in FIXED_CANDIDATE_IDS:
        raise ValueError("candidate-cell receipt identity changed")
    is_ablation = candidate.candidate_id == ABLATION_CANDIDATE_ID
    expected_role = "ablation" if is_ablation else "reference"
    if candidate.candidate_role != expected_role:
        raise ValueError("candidate-cell receipt role changed")
    if candidate.terminal_outcome is None:
        if tuple(phase.phase for phase in candidate.phases) != (
            "warmup",
            "tuning-prefix",
            "held-out",
        ):
            raise ValueError("candidate-cell receipt phase coverage changed")
        phase_measurements = {phase.phase: phase for phase in candidate.phases}
        retained_phases = (
            result.candidate.phases[1:]
            if expected_role == "reference"
            else result.candidate.phases[2:]
        )
        for retained_index, retained_phase in enumerate(retained_phases):
            if not retained_phase.retained_measurement:
                raise ValueError("candidate retained phase role changed")
            if retained_phase.outcome != "complete":
                continue
            if type(retained_phase.serialized_categories) is not tuple:
                raise ValueError("complete retained phase lost its serialized inventory")
            one_time = next(
                (
                    category
                    for category in retained_phase.serialized_categories
                    if category.category == "one-time-evaluation-key-material"
                ),
                None,
            )
            if one_time is None:
                raise ValueError("candidate retained phase lost its one-time category")
            expected_count = int(retained_index == 0)
            if (
                one_time.serialization_equivalence_class_count != expected_count
                or one_time.protocol_object_count != expected_count
                or (one_time.charged_byte_count > 0) != bool(expected_count)
            ):
                raise ValueError(
                    "one-time evaluation-key inventory must occur exactly once in the "
                    "first retained phase"
                )
    else:
        if (
            candidate.phases
            or candidate.terminal_outcome not in _OUTCOMES - {"complete", "ineligible"}
            or type(candidate.terminal_failure_code) is not str
            or not candidate.terminal_failure_code
            or candidate.receipt_origin != "controller-terminal-null-projection"
        ):
            raise ValueError("candidate-cell terminal receipt is not one closed null projection")
        phase_measurements = {
            phase: Day1BWorkerPhaseReceipt(
                phase=phase,
                retained_measurement=True,
                outcome=candidate.terminal_outcome,
                failure_code=candidate.terminal_failure_code,
                update_primitive_counts=None,
                query_primitive_counts=None,
                serialized_categories=None,
                worker_declared_phase_audit=None,
            )
            for phase in (
                ("tuning-prefix", "held-out") if expected_role == "reference" else ("held-out",)
            )
        }
    records: list[dict[str, object]] = []
    ledgers: list[dict[str, object]] = []
    if expected_role == "reference":
        record, ledger = _physical_record_and_ledger(
            phase_measurements["tuning-prefix"],
            trace=trace,
            cell=cell,
            phase="tuning-prefix",
            candidate_id=candidate.candidate_id,
            candidate_role="reference",
            selection_source="fixed-reference-tuning-prefix",
            worker_object_receipt_spool_sha256=(result.object_receipt_spool_sha256),
        )
        records.append(record)
        ledgers.append(ledger)
    record, ledger = _physical_record_and_ledger(
        phase_measurements["held-out"],
        trace=trace,
        cell=cell,
        phase="held-out",
        candidate_id=candidate.candidate_id,
        candidate_role=expected_role,
        selection_source=("fixed-ablation-held-out" if is_ablation else "fixed-reference-held-out"),
        worker_object_receipt_spool_sha256=(result.object_receipt_spool_sha256),
    )
    records.append(record)
    ledgers.append(ledger)
    return records, ledgers


class _UnitObjectReceiptArchive:
    """Disk-backed unit spool and cross-invocation ADR-0005 no-reuse registry."""

    def __init__(self) -> None:
        self._file: BinaryIO = tempfile.TemporaryFile(mode="w+b")  # noqa: SIM115
        self._registry = sqlite3.connect("")
        self._registry.execute("PRAGMA journal_mode=OFF")
        self._registry.execute("PRAGMA synchronous=OFF")
        self._registry.execute("PRAGMA temp_store=FILE")
        self._registry.execute(
            "CREATE TABLE f1m_bindings (query_id TEXT NOT NULL, version_id TEXT NOT NULL, "
            "output_plan_digest TEXT NOT NULL, component_id TEXT NOT NULL, "
            "output_block_id TEXT NOT NULL, PRIMARY KEY(query_id, version_id, "
            "output_plan_digest, component_id, output_block_id)) WITHOUT ROWID"
        )
        self._registry.execute(
            "CREATE TABLE f1m_payload_digests (digest TEXT PRIMARY KEY NOT NULL) WITHOUT ROWID"
        )
        self._registry.execute(
            "CREATE TABLE f1m_batch_plans (digest TEXT PRIMARY KEY NOT NULL) WITHOUT ROWID"
        )
        self._ledger_identity_sha256: str | None = None
        self._ledger_root_after_preparation_sha256: str | None = None
        self._hasher = hashlib.sha256()
        self.line_count = 0
        self.byte_count = 0
        self._sealed = False

    def accept_candidate_receipt(self, receipt: Day1BWorkerCellReceipt) -> None:
        if self._sealed or type(receipt) is not Day1BWorkerCellReceipt:
            raise ValueError("unit ledger registry requires one exact unsealed candidate receipt")
        identity = _require_sha256(
            receipt.pre_dispatch_ledger_identity_sha256,
            "candidate-cell ledger identity",
        )
        root_before = _require_sha256(
            receipt.pre_dispatch_ledger_root_before_sha256,
            "candidate-cell ledger root before",
        )
        root_after = _require_sha256(
            receipt.pre_dispatch_ledger_root_after_preparation_sha256,
            "candidate-cell ledger root after preparation",
        )
        batch_plan = _require_sha256(
            receipt.pre_dispatch_batch_plan_sha256,
            "candidate-cell batch plan",
        )
        if self._ledger_identity_sha256 is None:
            self._ledger_identity_sha256 = identity
        elif identity != self._ledger_identity_sha256:
            raise ValueError("candidate-cell invocations splice different F1-M ledgers")
        if (
            self._ledger_root_after_preparation_sha256 is not None
            and root_before != self._ledger_root_after_preparation_sha256
        ):
            raise ValueError("candidate-cell F1-M ledger transition chain is not contiguous")
        try:
            self._registry.execute(
                "INSERT INTO f1m_batch_plans(digest) VALUES (?)",
                (batch_plan,),
            )
        except sqlite3.IntegrityError as error:
            raise ValueError(
                "candidate-cell F1-M batch transition plan was reused within the unit"
            ) from error
        self._ledger_root_after_preparation_sha256 = root_after

    def write(self, line: bytes) -> int:
        if self._sealed or type(line) is not bytes or not line.endswith(b"\n"):
            raise ValueError("unit object-receipt archive only accepts canonical JSON lines")
        try:
            document = json.loads(line.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("worker object receipt line is not canonical ASCII JSON") from error
        if type(document) is not dict or canonical_json_bytes(document) != line:
            raise ValueError("worker object receipt line is not canonical closed JSON")
        category = document.get("category")
        serialized_object = document.get("object")
        if type(category) is not str or type(serialized_object) is not dict:
            raise ValueError("worker object receipt line lost category/object identity")
        f1m_binding = serialized_object.get("f1m_binding")
        if category in DAY1B_WORKER_REQUIRED_F1M_BINDING_CATEGORIES:
            if type(f1m_binding) is not dict:
                raise ValueError("F1-M object receipt lost its ADR-0005 binding")
            no_reuse_key = tuple(
                f1m_binding.get(field)
                for field in (
                    "query_id",
                    "version_id",
                    "output_plan_digest",
                    "component_id",
                    "output_block_id",
                )
            )
            if any(type(value) is not str or not value for value in no_reuse_key):
                raise ValueError("F1-M object receipt binding tuple is malformed")
            try:
                self._registry.execute(
                    "INSERT INTO f1m_bindings VALUES (?, ?, ?, ?, ?)",
                    no_reuse_key,
                )
            except sqlite3.IntegrityError as error:
                raise ValueError(
                    "F1-M ADR-0005 binding was reused across candidate-cell invocations"
                ) from error
            payload_digest = _require_sha256(
                serialized_object.get("serialized_sha256"),
                "F1-M serialized payload diagnostic digest",
            )
            try:
                self._registry.execute(
                    "INSERT INTO f1m_payload_digests(digest) VALUES (?)",
                    (payload_digest,),
                )
            except sqlite3.IntegrityError as error:
                raise ValueError(
                    "F1-M serialized payload digest repeated across the Day1B unit"
                ) from error
        elif f1m_binding is not None:
            raise ValueError("non-F1-M object receipt carries an F1-M binding")
        written = self._file.write(line)
        if written != len(line):
            raise OSError("unit object-receipt archive write was incomplete")
        self._hasher.update(line)
        self.line_count += 1
        self.byte_count += len(line)
        return written

    def seal(self) -> tuple[str, int, int]:
        self._file.flush()
        self._sealed = True
        return self._hasher.hexdigest(), self.line_count, self.byte_count

    def copy_to(self, destination: BinaryIO) -> tuple[str, int, int]:
        if not self._sealed:
            raise RuntimeError("unit object-receipt archive is not sealed")
        self._file.seek(0)
        hasher = hashlib.sha256()
        line_count = 0
        byte_count = 0
        while line := self._file.readline():
            written = destination.write(line)
            if written != len(line):
                raise OSError("installed object-receipt archive write was incomplete")
            hasher.update(line)
            line_count += 1
            byte_count += len(line)
        observed = (hasher.hexdigest(), line_count, byte_count)
        expected = (self._hasher.hexdigest(), self.line_count, self.byte_count)
        if observed != expected:
            raise RuntimeError("unit object-receipt archive changed after sealing")
        return observed

    def close(self) -> None:
        self._registry.close()
        self._file.close()


def _append_candidate_object_receipts(
    evidence: Day1BClaimedWorkerEvidence,
    archive: _UnitObjectReceiptArchive,
) -> None:
    """Revalidate one sealed invocation spool, then append its canonical lines."""

    with tempfile.TemporaryFile(mode="w+b") as candidate_copy:
        copied_sha256 = evidence.copy_object_receipts_to(candidate_copy)
        if copied_sha256 != evidence.receipt.object_receipt_spool_sha256:
            raise Day1BWorkerProtocolError(
                "candidate object-receipt copy differs from its sealed digest"
            )
        candidate_copy.seek(0)
        copied_line_count = 0
        while line := candidate_copy.readline():
            archive.write(line)
            copied_line_count += 1
        if copied_line_count != evidence.object_receipt_line_count:
            raise Day1BWorkerProtocolError(
                "candidate object-receipt copy differs from its sealed line count"
            )


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
    object_receipt_archive: _UnitObjectReceiptArchive,
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
        with (staging / _OBJECT_RECEIPT_FILENAME).open("xb") as handle:
            object_receipt_sha, object_receipt_lines, object_receipt_size = (
                object_receipt_archive.copy_to(handle)
            )
            handle.flush()
            os.fsync(handle.fileno())

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
            _OBJECT_RECEIPT_FILENAME: {
                "sha256": object_receipt_sha,
                "byte_count": object_receipt_size,
                "jsonl_line_count": object_receipt_lines,
            },
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
            _OBJECT_RECEIPT_FILENAME: (object_receipt_sha, object_receipt_size),
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
            serialized_object_receipt_path=output_dir / _OBJECT_RECEIPT_FILENAME,
            checksums_path=output_dir / _CHECKSUM_FILENAME,
            manifest_sha256=manifest_sha,
            heldout_fragment_sha256=fragment_sha,
            schedule_sha256=schedule_sha,
            serialization_ledger_sha256=ledger_sha,
            serialized_object_receipt_sha256=object_receipt_sha,
            checksums_sha256=checksums_sha,
        )
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
            lock_path.unlink(missing_ok=True)
        shutil.rmtree(staging, ignore_errors=True)


@dataclass(frozen=True, slots=True)
class _Day1BWorkerContractSeed:
    """Core-owned candidate×cell facts; the adapter may bind only measured expectations."""

    invocation_id: str
    trace_manifest_sha256: str
    event_schedule_sha256: str
    query_vector_sha256: str
    candidate_catalog_sha256: str
    resource_policy_sha256: str
    freshness: str
    rho: str
    candidate: Day1BWorkerCandidateSpec
    phase_ranges: tuple[Day1BWorkerPhaseRange, ...]
    resource_limits: Day1BWorkerResourceLimits

    def bind(
        self,
        *,
        expected_f1m_binding_set_sha256: str,
        expected_f1m_binding_count: int,
        expected_serialized_equivalence_class_count: int,
        expected_f1m_cardinality_derivation_root_sha256: str,
    ) -> Day1BWorkerProtocolContract:
        return Day1BWorkerProtocolContract(
            invocation_id=self.invocation_id,
            trace_manifest_sha256=self.trace_manifest_sha256,
            event_schedule_sha256=self.event_schedule_sha256,
            query_vector_sha256=self.query_vector_sha256,
            candidate_catalog_sha256=self.candidate_catalog_sha256,
            resource_policy_sha256=self.resource_policy_sha256,
            freshness=self.freshness,
            rho=self.rho,
            candidate=self.candidate,
            phase_ranges=self.phase_ranges,
            primitive_names=PRIMITIVE_NAMES,
            serialized_categories=SERIALIZED_PROTOCOL_OBJECT_CATEGORIES,
            f1m_binding_categories=DAY1B_WORKER_REQUIRED_F1M_BINDING_CATEGORIES,
            expected_f1m_binding_set_sha256=expected_f1m_binding_set_sha256,
            expected_f1m_binding_count=expected_f1m_binding_count,
            expected_serialized_equivalence_class_count=(
                expected_serialized_equivalence_class_count
            ),
            expected_f1m_cardinality_derivation_root_sha256=(
                expected_f1m_cardinality_derivation_root_sha256
            ),
            resource_limits=self.resource_limits,
        )

    def require_exact_bound_contract(self, contract: Day1BWorkerProtocolContract) -> None:
        if type(contract) is not Day1BWorkerProtocolContract:
            raise TypeError("worker launch contract must be exact typed protocol input")
        expected = self.bind(
            expected_f1m_binding_set_sha256=contract.expected_f1m_binding_set_sha256,
            expected_f1m_binding_count=contract.expected_f1m_binding_count,
            expected_serialized_equivalence_class_count=(
                contract.expected_serialized_equivalence_class_count
            ),
            expected_f1m_cardinality_derivation_root_sha256=(
                contract.expected_f1m_cardinality_derivation_root_sha256
            ),
        )
        if contract != expected:
            raise Day1BWorkerProtocolError(
                "worker launch retargeted repository-owned candidate-cell contract facts"
            )


def _candidate_policy_digest(candidate: RegisteredCandidate) -> str:
    return _digest(
        {
            "candidate_id": candidate.candidate_id,
            "candidate_role": candidate.role,
            "packed_coo_segment_capacity": candidate.packed_coo_segment_capacity,
            "periodic_repack_windows": candidate.periodic_repack_windows,
            "reserved_slack_beta": (
                None
                if candidate.reserved_slack_beta is None
                else str(candidate.reserved_slack_beta)
            ),
            "strategy": candidate.strategy,
        }
    )


def _candidate_worker_contract_seed(
    *,
    trace: _Day1BTraceInput,
    program: _PublicationScheduleAdapter,
    freshness: Fraction,
    candidate: RegisteredCandidate,
    cell_binding_sha256: str,
    candidate_catalog_sha256: str,
    resource_policy: PublicationDay1BResourcePolicy,
    resource_policy_sha256: str,
) -> _Day1BWorkerContractSeed:
    invocation_id = _digest(
        {
            "candidate_id": candidate.candidate_id,
            "cell_binding_sha256": cell_binding_sha256,
            "schema_version": "dynamic-cssc-publication-day1b-candidate-cell-invocation-v1",
        }
    )
    return _Day1BWorkerContractSeed(
        invocation_id=invocation_id,
        trace_manifest_sha256=trace.trace_manifest_sha256,
        event_schedule_sha256=program.canonical_schedule_sha256,
        query_vector_sha256=trace.query_vector_sha256,
        candidate_catalog_sha256=candidate_catalog_sha256,
        resource_policy_sha256=resource_policy_sha256,
        freshness=_fraction_text(freshness),
        rho=_fraction_text(program.rho),
        candidate=Day1BWorkerCandidateSpec(
            candidate_id=candidate.candidate_id,
            candidate_role=candidate.role,
            strategy=candidate.strategy,
            f1m_policy=(
                "uniform-random-or-zero"
                if candidate.strategy == "Packed-COO-Cloud-Segmented-Delta"
                else "overlap-only"
            ),
            candidate_policy_digest=_candidate_policy_digest(candidate),
            retained_phases=(
                ("tuning-prefix", "held-out") if candidate.role == "reference" else ("held-out",)
            ),
        ),
        phase_ranges=tuple(
            Day1BWorkerPhaseRange(phase.name, phase.start, phase.end)
            for phase in program.phase_ranges
        ),
        resource_limits=resource_policy.to_worker_limits(),
    )


def _complete_cell_audit(
    program: _PublicationScheduleAdapter,
    freshness: Fraction,
) -> _CellAudit:
    stream = _AuditedWindowStream(
        program.stream_windows(freshness),
        program.phase_ranges,
        program.rho,
    )
    for _window in stream:
        pass
    return stream.finish()


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
    if not callable(getattr(execution_adapter, "execute_candidate_cell", None)):
        raise TypeError("execution_adapter must provide the candidate-cell streaming seam")

    programs = tuple(trace.compile_schedule(Fraction(rho)) for rho in RHO_VALUES)
    for program, rho in zip(programs, (Fraction(value) for value in RHO_VALUES), strict=True):
        _validate_program(program, trace=trace, rho=rho)

    trace_unit = _trace_unit_document(trace, source_authority)
    registration = asdict(candidate_catalog.registration)
    catalog_document = {
        "registration": registration,
        "registration_sha256": _digest(registration),
        "fixed_candidate_ids": list(FIXED_CANDIDATE_IDS),
        "reference_candidate_ids": list(REFERENCE_CANDIDATE_IDS),
        "ablation_candidate_ids": [ABLATION_CANDIDATE_ID],
    }
    candidate_catalog_sha256 = _digest(catalog_document)
    resource_document = resource_policy.to_document()
    resource_policy_sha256 = str(resource_document["resource_policy_sha256"])
    cells: list[dict[str, object]] = []
    records: list[dict[str, object]] = []
    ledgers: list[dict[str, object]] = []
    cell_execution_receipts: list[dict[str, object]] = []
    candidate_cell_receipt_count = 0
    object_receipt_archive = _UnitObjectReceiptArchive()
    try:
        for freshness_text in FRESHNESS_VALUES:
            freshness = Fraction(freshness_text)
            for program in programs:
                audit = _complete_cell_audit(program, freshness)
                cell = _cell_document(
                    trace_unit,
                    trace,
                    source_authority,
                    program,
                    freshness,
                    audit,
                )
                tuning_records: list[dict[str, object]] = []
                tuning_ledgers: list[dict[str, object]] = []
                heldout_records: list[dict[str, object]] = []
                heldout_ledgers: list[dict[str, object]] = []
                candidate_receipts: list[dict[str, object]] = []
                peak_resident_memory_bytes = 0
                peak_scratch_bytes = 0

                for candidate in candidates:
                    audited_windows = _AuditedWindowStream(
                        program.stream_windows(freshness),
                        program.phase_ranges,
                        program.rho,
                    )
                    seed = _candidate_worker_contract_seed(
                        trace=trace,
                        program=program,
                        freshness=freshness,
                        candidate=candidate,
                        cell_binding_sha256=str(cell["cell_binding_sha256"]),
                        candidate_catalog_sha256=candidate_catalog_sha256,
                        resource_policy=resource_policy,
                        resource_policy_sha256=resource_policy_sha256,
                    )
                    launch: _Day1BWorkerLaunch | None = None
                    invocation_consumed = False
                    try:
                        launch = execution_adapter.execute_candidate_cell(
                            windows=audited_windows,
                            contract_seed=seed,
                        )
                        if type(launch) is not _Day1BWorkerLaunch:
                            raise TypeError(
                                "execution adapter must return one exact candidate-cell launch"
                            )
                        candidate_audit = audited_windows.finish()
                        if candidate_audit != audit:
                            raise Day1BWorkerProtocolError(
                                "candidate did not consume the canonical complete cell schedule"
                            )
                        seed.require_exact_bound_contract(launch.contract)
                        evidence_capability = consume_day1b_worker_frames(
                            launch.frame_chunks,
                            contract=launch.contract,
                            invocation_capability=launch.invocation_capability,
                        )
                        invocation_consumed = True
                        with claim_day1b_worker_evidence(evidence_capability) as evidence:
                            receipt = evidence.receipt
                            if (
                                receipt.input_binding_sha256 != launch.contract.input_binding_sha256
                                or receipt.controller_schedule_phase_audits != audit.phase_audits
                            ):
                                raise Day1BWorkerProtocolError(
                                    "candidate receipt changed its bound input or schedule audit"
                                )
                            object_receipt_archive.accept_candidate_receipt(receipt)
                            _append_candidate_object_receipts(
                                evidence,
                                object_receipt_archive,
                            )
                            candidate_records, candidate_ledgers = _records_for_candidate_cell(
                                receipt,
                                trace=trace,
                                cell=cell,
                            )
                            candidate_receipts.append(receipt.to_document())
                            peak_resident_memory_bytes = max(
                                peak_resident_memory_bytes,
                                receipt.candidate.peak_resident_memory_bytes,
                            )
                            peak_scratch_bytes = max(
                                peak_scratch_bytes,
                                receipt.candidate.peak_scratch_bytes,
                            )
                    except BaseException as error:
                        if launch is not None and not invocation_consumed:
                            with suppress(BaseException):
                                abandon_day1b_worker_invocation(launch.invocation_capability)
                        if isinstance(
                            error,
                            (Day1BWorkerProtocolError, TypeError, ValueError, OSError),
                        ):
                            raise PublicationDay1BHold(
                                "HOLD: candidate-cell worker evidence failed closed validation"
                            ) from error
                        raise

                    if candidate.role == "reference":
                        if len(candidate_records) != 2 or len(candidate_ledgers) != 2:
                            raise RuntimeError(
                                "reference candidate did not yield tuning plus held-out records"
                            )
                        tuning_records.append(candidate_records[0])
                        tuning_ledgers.append(candidate_ledgers[0])
                        heldout_records.append(candidate_records[1])
                        heldout_ledgers.append(candidate_ledgers[1])
                    else:
                        if (
                            candidate.candidate_id != ABLATION_CANDIDATE_ID
                            or len(candidate_records) != 1
                            or len(candidate_ledgers) != 1
                        ):
                            raise RuntimeError(
                                "ablation candidate did not yield one held-out record"
                            )
                        heldout_records.append(candidate_records[0])
                        heldout_ledgers.append(candidate_ledgers[0])

                if (
                    len(candidate_receipts) != len(FIXED_CANDIDATE_IDS)
                    or len(tuning_records) != len(REFERENCE_CANDIDATE_IDS)
                    or len(heldout_records) != len(FIXED_CANDIDATE_IDS)
                ):
                    raise RuntimeError("candidate-cell coverage did not close canonically")
                cell_records = [*tuning_records, *heldout_records]
                cell_ledgers = [*tuning_ledgers, *heldout_ledgers]
                cells.append(cell)
                records.extend(cell_records)
                ledgers.extend(cell_ledgers)
                candidate_cell_receipt_count += len(candidate_receipts)
                cell_execution_receipts.append(
                    {
                        "cell_binding_sha256": cell["cell_binding_sha256"],
                        "freshness_seconds": cell["freshness_seconds"],
                        "rho": cell["rho"],
                        "phase_receipts": list(audit.phase_receipts),
                        "candidate_cell_receipts": candidate_receipts,
                        "candidate_cell_receipt_count": len(candidate_receipts),
                        "physical_record_count": len(cell_records),
                        "candidate_retry_count": 0,
                        "peak_resident_memory_bytes": peak_resident_memory_bytes,
                        "peak_scratch_bytes": peak_scratch_bytes,
                    }
                )
        if (
            len(cells),
            candidate_cell_receipt_count,
            len(records),
            len(ledgers),
        ) != (18, 252, 486, 486):
            raise RuntimeError("Day1B unit cardinality did not close at 18/252/486/486")
        object_receipt_archive.seal()

        fragment = {
            "schema_version": DAY1B_UNIT_FRAGMENT_SCHEMA,
            "experiment_source_git_sha": source_authority.git_sha,
            "trace_units": [trace_unit],
            "cell_bindings": cells,
            "records": records,
        }
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
                "candidate_cell_receipt_count": 252,
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
            object_receipt_archive=object_receipt_archive,
            programs=programs,
            manifest_base=manifest_base,
            resource_policy=resource_policy,
        )
    finally:
        object_receipt_archive.close()


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
    "PublicationDay1BHold",
    "PublicationDay1BResourcePolicy",
    "PublicationDay1BUnitBundle",
    "produce_publication_day1b_unit",
)
