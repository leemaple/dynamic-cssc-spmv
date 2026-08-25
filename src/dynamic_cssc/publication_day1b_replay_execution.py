"""Seal one same-replay Day 1B representative query without authorizing it.

Every query-bearing layout contributes a compact canonical binding to an
ordered stream root.  Only the first query-bearing layout in the candidate's
first retained phase is kept as a typed private representative.  The resulting
single-use capability proves replay continuity inside this process, but it does
not grant runtime, worker, dispatch, formal, or publication authority.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Literal

from dynamic_cssc.cssc import PublishedComponent
from dynamic_cssc.day1_registry import RegisteredCandidate
from dynamic_cssc.plaintext_oracle import direct_spmv
from dynamic_cssc.publication_day1b_accounting import (
    Day1BAccountingDomain,
    Day1BQueryWindowAccounting,
    PublicationDay1BAccounting,
    _candidate_document,
    replay_publication_day1b_candidate_cell,
)
from dynamic_cssc.publication_day1b_layout_execution import (
    Day1BQueryLayoutExecution,
)
from dynamic_cssc.publication_schedule import ExactPublicationWindow
from dynamic_cssc.publication_traces import PUBLICATION_QUERY_VECTOR_SCHEMA
from dynamic_cssc.strategy_state import PackedCOOEntry, PackedCOOSegment
from dynamic_cssc.strong_packed_coo import decode_segmented_delta

DAY1B_QUERY_EXECUTION_BINDING_SCHEMA = (
    "dynamic-cssc-publication-day1b-query-execution-binding-v2"
)
DAY1B_QUERY_EXECUTION_STREAM_SCHEMA = (
    "dynamic-cssc-publication-day1b-query-execution-stream-v2"
)
DAY1B_REPLAY_EXECUTION_RECEIPT_SCHEMA = (
    "dynamic-cssc-publication-day1b-replay-execution-receipt-v2"
)
DAY1B_REPRESENTATIVE_SELECTION_RULE = (
    "canonical-first-query-bearing-window-of-first-retained-phase-v1"
)

RetainedPhase = Literal["tuning-prefix", "held-out"]
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RETAINED_PHASE_SETS = (
    ("tuning-prefix", "held-out"),
    ("held-out",),
)
_LOGICAL_STATE_SCHEMA = "dynamic-cssc-publication-day1b-query-logical-state-v1"
_EXPECTED_OUTPUT_SCHEMA = "dynamic-cssc-publication-day1b-query-expected-output-v1"
_FROZEN_PLAINTEXT_MODULUS = 65537


class Day1BReplayExecutionError(ValueError):
    """The same-replay representative binding failed closed."""


def _canonical_bytes(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise Day1BReplayExecutionError(
            "query-execution value is not canonical JSON"
        ) from error
    return (rendered + "\n").encode("ascii")


def _sha256_document(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _require_sha256(value: object, field: str) -> str:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise Day1BReplayExecutionError(f"{field} must be a lowercase SHA-256")
    return value


def _sequence_root(*, count: int, stream_sha256: str, schema: str) -> str:
    return _sha256_document(
        {
            "element_count": count,
            "element_stream_sha256": stream_sha256,
            "schema_version": schema,
        }
    )


def _decode_query_vector(
    content: object,
    expected_sha256: object,
) -> tuple[int, ...]:
    if type(content) is not bytes or not content:
        raise Day1BReplayExecutionError(
            "query vector must retain nonempty exact canonical bytes"
        )
    digest = _require_sha256(expected_sha256, "query vector")
    if hashlib.sha256(content).hexdigest() != digest:
        raise Day1BReplayExecutionError("query-vector bytes differ from their digest")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, member in pairs:
            if key in value:
                raise Day1BReplayExecutionError("query vector contains duplicate keys")
            value[key] = member
        return value

    try:
        payload = json.loads(
            content.decode("ascii"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                Day1BReplayExecutionError(
                    f"query vector contains non-finite JSON: {token}"
                )
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Day1BReplayExecutionError(
            "query vector is not canonical ASCII JSON"
        ) from error
    if type(payload) is not dict or content != _canonical_bytes(payload):
        raise Day1BReplayExecutionError("query vector is not canonical JSON")
    values = payload.get("values")
    if (
        payload.get("schema_version") != PUBLICATION_QUERY_VECTOR_SCHEMA
        or type(values) is not list
        or not values
        or any(type(value) is not int or value not in {-1, 0, 1} for value in values)
    ):
        raise Day1BReplayExecutionError(
            "query vector does not contain the frozen nonempty ternary payload"
        )
    return tuple(values)


def _component_state(component: PublishedComponent) -> dict[tuple[int, int], int]:
    if type(component) is not PublishedComponent:
        raise Day1BReplayExecutionError(
            "query execution contains a non-exact published component"
        )
    state: dict[tuple[int, int], int] = {}
    for chunk in component.chunks:
        for coordinate, value in zip(
            chunk.slot_coordinates,
            chunk.values,
            strict=True,
        ):
            if coordinate is None or value == 0:
                continue
            if coordinate in state:
                raise Day1BReplayExecutionError(
                    "published component repeats an active logical coordinate"
                )
            state[coordinate] = value
    return state


def _logical_state(
    execution: Day1BQueryLayoutExecution,
) -> tuple[int, int, dict[tuple[int, int], int]]:
    if type(execution) is not Day1BQueryLayoutExecution:
        raise TypeError("execution must be an exact Day1BQueryLayoutExecution")
    logical: dict[tuple[int, int], int] = {}
    if execution.ordinary_compilation is not None:
        compiled = execution.ordinary_compilation
        if not compiled.components:
            raise Day1BReplayExecutionError(
                "ordinary representative has no published component"
            )
        reference = compiled.components[0].layout_spec
        for component in compiled.components:
            if component.layout_spec != reference:
                raise Day1BReplayExecutionError(
                    "ordinary representative component domains differ"
                )
            component_state = _component_state(component)
            if set(component_state) & set(logical):
                raise Day1BReplayExecutionError(
                    "ordinary representative components overlap logically"
                )
            logical.update(component_state)
        for segment in compiled.client_lane_segments:
            if (
                type(segment) is not PackedCOOSegment
                or type(segment.segment_id) is not str
                or not segment.segment_id
                or segment.version_id != compiled.components[0].version_id
                or type(segment.capacity) is not int
                or not 0 < segment.capacity <= reference.effective_slots
                or type(segment.entries) is not tuple
                or len(segment.entries) != segment.capacity
            ):
                raise Day1BReplayExecutionError(
                    "ordinary representative client-lane segment is invalid"
                )
            for entry in segment.entries:
                if entry is None or (
                    type(entry) is PackedCOOEntry and entry.value == 0
                ):
                    continue
                if (
                    type(entry) is not PackedCOOEntry
                    or type(entry.coordinate) is not tuple
                    or len(entry.coordinate) != 2
                    or any(type(axis) is not int for axis in entry.coordinate)
                    or type(entry.value) is not int
                    or not 0 <= entry.coordinate[0] < reference.rows
                    or not 0 <= entry.coordinate[1] < reference.cols
                    or entry.coordinate in logical
                ):
                    raise Day1BReplayExecutionError(
                        "ordinary representative client-lane state is inconsistent"
                    )
                logical[entry.coordinate] = entry.value
        return reference.rows, reference.cols, logical

    bundle = execution.strong_bundle
    assert bundle is not None
    reference = bundle.base.layout_spec
    base = _component_state(bundle.base)
    delta = decode_segmented_delta(bundle.delta)
    if (
        bundle.delta.rows != reference.rows
        or bundle.delta.cols != reference.cols
        or set(base) & set(delta)
    ):
        raise Day1BReplayExecutionError(
            "strong representative base and delta domains are inconsistent"
        )
    logical.update(base)
    logical.update(delta)
    return reference.rows, reference.cols, logical


def _state_and_expected_output(
    execution: Day1BQueryLayoutExecution,
    *,
    query_vector: tuple[int, ...],
    modulus: int,
) -> tuple[str, tuple[int, ...], str]:
    rows, cols, logical = _logical_state(execution)
    if len(query_vector) != cols:
        raise Day1BReplayExecutionError(
            "query vector length differs from the same-replay matrix domain"
        )
    try:
        expected = direct_spmv(
            logical,
            query_vector,
            rows=rows,
            cols=cols,
            modulus=modulus,
        )
    except ValueError as error:
        raise Day1BReplayExecutionError(
            "same-replay logical state cannot produce the expected output"
        ) from error
    state_sha256 = _sha256_document(
        {
            "cols": cols,
            "entries": [
                [row, col, value]
                for (row, col), value in sorted(logical.items())
            ],
            "rows": rows,
            "schema_version": _LOGICAL_STATE_SCHEMA,
        }
    )
    expected_sha256 = _sha256_document(
        {
            "modulus": modulus,
            "schema_version": _EXPECTED_OUTPUT_SCHEMA,
            "values": list(expected),
        }
    )
    return state_sha256, expected, expected_sha256


def _require_pair(
    descriptor: Day1BQueryWindowAccounting,
    execution: Day1BQueryLayoutExecution,
) -> None:
    if type(descriptor) is not Day1BQueryWindowAccounting:
        raise TypeError("descriptor must be an exact Day1BQueryWindowAccounting")
    if type(execution) is not Day1BQueryLayoutExecution:
        raise TypeError("execution must be an exact Day1BQueryLayoutExecution")
    if (
        execution.phase != descriptor.phase
        or execution.window_index != descriptor.window_index
        or execution.accepted_group_start != descriptor.accepted_group_start
        or execution.accepted_group_end != descriptor.accepted_group_end
        or execution.first_global_query_ordinal
        != descriptor.first_global_query_ordinal
        or execution.query_count != descriptor.query_count
        or execution.query_plan != descriptor.query_plan
    ):
        raise Day1BReplayExecutionError(
            "query descriptor and same-replay execution carrier are not one pair"
        )


@dataclass(frozen=True, slots=True)
class Day1BQueryExecutionBinding:
    candidate_id: str
    candidate_role: str
    candidate_policy_sha256: str
    retained_phases: tuple[RetainedPhase, ...]
    phase: str
    window_index: int
    first_global_query_ordinal: int
    logical_query_multiplicity: int
    execution_kind: str
    descriptor_sha256: str
    version_id: str
    cloud_program_sha256: str
    output_plan_sha256: str
    execution_binding_sha256: str
    private_plan_sha256: str
    query_vector_sha256: str
    plaintext_modulus: int
    logical_state_sha256: str | None
    expected_output_sha256: str | None
    retained_private_bundle_count: int
    openfhe_execution_count: int = 0

    def __post_init__(self) -> None:
        expected_retained_phases = {
            "reference": ("tuning-prefix", "held-out"),
            "ablation": ("held-out",),
        }.get(self.candidate_role)
        if (
            type(self.candidate_id) is not str
            or not self.candidate_id
            or self.retained_phases != expected_retained_phases
            or self.plaintext_modulus != _FROZEN_PLAINTEXT_MODULUS
        ):
            raise Day1BReplayExecutionError(
                "query execution candidate role/phases/modulus are not frozen"
            )
        if self.phase not in {"warmup", "tuning-prefix", "held-out"}:
            raise Day1BReplayExecutionError("query execution phase is not frozen")
        for field in ("window_index", "first_global_query_ordinal"):
            value = getattr(self, field)
            if type(value) is not int or value < 0:
                raise Day1BReplayExecutionError(
                    f"query execution {field} must be a nonnegative strict integer"
                )
        if (
            type(self.logical_query_multiplicity) is not int
            or self.logical_query_multiplicity <= 0
            or self.retained_private_bundle_count not in {0, 1}
            or self.openfhe_execution_count != 0
        ):
            raise Day1BReplayExecutionError(
                "logical multiplicity, retained bundle count, or runtime count is invalid"
            )
        if self.execution_kind not in {"ordinary", "strong"}:
            raise Day1BReplayExecutionError("query execution kind is not closed")
        if type(self.version_id) is not str or not self.version_id:
            raise Day1BReplayExecutionError("query execution version is empty")
        for field in (
            "descriptor_sha256",
            "candidate_policy_sha256",
            "cloud_program_sha256",
            "output_plan_sha256",
            "execution_binding_sha256",
            "private_plan_sha256",
            "query_vector_sha256",
        ):
            _require_sha256(getattr(self, field), f"query execution {field}")
        oracle_digests = (self.logical_state_sha256, self.expected_output_sha256)
        if self.retained_private_bundle_count == 1:
            for field, value in zip(
                ("logical_state_sha256", "expected_output_sha256"),
                oracle_digests,
                strict=True,
            ):
                _require_sha256(value, f"representative query execution {field}")
        elif oracle_digests != (None, None):
            raise Day1BReplayExecutionError(
                "non-representative binding cannot retain private oracle digests"
            )

    def to_document(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "candidate_policy_sha256": self.candidate_policy_sha256,
            "candidate_role": self.candidate_role,
            "cloud_program_sha256": self.cloud_program_sha256,
            "descriptor_sha256": self.descriptor_sha256,
            "execution_binding_sha256": self.execution_binding_sha256,
            "execution_kind": self.execution_kind,
            "expected_output_sha256": self.expected_output_sha256,
            "first_global_query_ordinal": self.first_global_query_ordinal,
            "logical_query_multiplicity": self.logical_query_multiplicity,
            "logical_state_sha256": self.logical_state_sha256,
            "openfhe_execution_count": self.openfhe_execution_count,
            "output_plan_sha256": self.output_plan_sha256,
            "phase": self.phase,
            "private_plan_sha256": self.private_plan_sha256,
            "plaintext_modulus": self.plaintext_modulus,
            "query_vector_sha256": self.query_vector_sha256,
            "retained_phases": list(self.retained_phases),
            "retained_private_bundle_count": self.retained_private_bundle_count,
            "schema_version": DAY1B_QUERY_EXECUTION_BINDING_SCHEMA,
            "version_id": self.version_id,
            "window_index": self.window_index,
        }

    @property
    def binding_sha256(self) -> str:
        return _sha256_document(self.to_document())


def _binding_for_pair(
    descriptor: Day1BQueryWindowAccounting,
    execution: Day1BQueryLayoutExecution,
    *,
    candidate_id: str,
    candidate_role: str,
    candidate_policy_sha256: str,
    retained_phases: tuple[RetainedPhase, ...],
    query_vector: tuple[int, ...],
    query_vector_sha256: str,
    modulus: int,
    retain_private_bundle: bool,
) -> tuple[Day1BQueryExecutionBinding, tuple[int, ...] | None]:
    _require_pair(descriptor, execution)
    if type(retain_private_bundle) is not bool:
        raise TypeError("retain_private_bundle must be an exact boolean")
    if retain_private_bundle:
        logical_state_sha256, expected_output, expected_output_sha256 = (
            _state_and_expected_output(
                execution,
                query_vector=query_vector,
                modulus=modulus,
            )
        )
    else:
        logical_state_sha256 = None
        expected_output = None
        expected_output_sha256 = None
    plan = descriptor.query_plan
    return (
        Day1BQueryExecutionBinding(
            candidate_id=candidate_id,
            candidate_role=candidate_role,
            candidate_policy_sha256=candidate_policy_sha256,
            retained_phases=retained_phases,
            phase=descriptor.phase,
            window_index=descriptor.window_index,
            first_global_query_ordinal=descriptor.first_global_query_ordinal,
            logical_query_multiplicity=descriptor.query_count,
            execution_kind=execution.execution_kind,
            descriptor_sha256=_sha256_document(descriptor.to_document()),
            version_id=plan.version_id,
            cloud_program_sha256=plan.cloud_program_digest,
            output_plan_sha256=plan.output_plan_digest,
            execution_binding_sha256=plan.execution_binding_digest,
            private_plan_sha256=plan.private_plan_digest,
            query_vector_sha256=query_vector_sha256,
            plaintext_modulus=modulus,
            logical_state_sha256=logical_state_sha256,
            expected_output_sha256=expected_output_sha256,
            retained_private_bundle_count=int(retain_private_bundle),
        ),
        expected_output,
    )


@dataclass(frozen=True, slots=True)
class Day1BReplayExecutionReceipt:
    candidate_id: str
    candidate_role: str
    candidate_policy_sha256: str
    retained_phases: tuple[RetainedPhase, ...]
    accounting_sha256: str
    window_stream_sha256: str
    query_window_stream_sha256: str
    query_execution_binding_stream_sha256: str
    query_execution_binding_count: int
    query_vector_sha256: str
    plaintext_modulus: int
    representative_query_execution_binding_sha256: str
    representative_phase: str
    representative_window_index: int
    terminal_version_id: str
    terminal_logical_state_sha256: str
    state_reset_count: int

    def __post_init__(self) -> None:
        if type(self.candidate_id) is not str or not self.candidate_id:
            raise Day1BReplayExecutionError("candidate replay identity is empty")
        expected_retained_phases = {
            "reference": ("tuning-prefix", "held-out"),
            "ablation": ("held-out",),
        }.get(self.candidate_role)
        if (
            self.retained_phases != expected_retained_phases
            or self.plaintext_modulus != _FROZEN_PLAINTEXT_MODULUS
            or self.representative_phase != self.retained_phases[0]
        ):
            raise Day1BReplayExecutionError(
                "candidate replay role/phases/modulus are not frozen"
            )
        for field in (
            "candidate_policy_sha256",
            "accounting_sha256",
            "window_stream_sha256",
            "query_window_stream_sha256",
            "query_execution_binding_stream_sha256",
            "query_vector_sha256",
            "representative_query_execution_binding_sha256",
            "terminal_logical_state_sha256",
        ):
            _require_sha256(getattr(self, field), f"candidate replay {field}")
        if (
            type(self.query_execution_binding_count) is not int
            or self.query_execution_binding_count <= 0
            or type(self.representative_window_index) is not int
            or self.representative_window_index < 0
            or self.representative_phase not in {"tuning-prefix", "held-out"}
            or self.state_reset_count != 0
            or type(self.terminal_version_id) is not str
            or not self.terminal_version_id
        ):
            raise Day1BReplayExecutionError(
                "candidate replay representative/count/terminal fields are invalid"
            )

    def _body_document(self) -> dict[str, object]:
        return {
            "accounting_sha256": self.accounting_sha256,
            "candidate_id": self.candidate_id,
            "candidate_policy_sha256": self.candidate_policy_sha256,
            "candidate_role": self.candidate_role,
            "candidate_replay_continuity_verified": True,
            "complete_cost_claim_allowed": False,
            "formal_authority_granted": False,
            "heldout_dispatch_authorized": False,
            "production_execution_admissible": False,
            "publication_authority": False,
            "query_execution_binding_count": self.query_execution_binding_count,
            "query_execution_binding_stream_sha256": (
                self.query_execution_binding_stream_sha256
            ),
            "query_vector_sha256": self.query_vector_sha256,
            "query_window_stream_sha256": self.query_window_stream_sha256,
            "representative_phase": self.representative_phase,
            "representative_query_execution_binding_sha256": (
                self.representative_query_execution_binding_sha256
            ),
            "representative_selection_rule": DAY1B_REPRESENTATIVE_SELECTION_RULE,
            "representative_window_index": self.representative_window_index,
            "schema_version": DAY1B_REPLAY_EXECUTION_RECEIPT_SCHEMA,
            "state_reset_count": self.state_reset_count,
            "terminal_logical_state_sha256": self.terminal_logical_state_sha256,
            "terminal_version_id": self.terminal_version_id,
            "typed_query_layout_verified": True,
            "representative_expected_output_verified": True,
            "openfhe_execution_verified": False,
            "plaintext_modulus": self.plaintext_modulus,
            "retained_phases": list(self.retained_phases),
            "window_stream_sha256": self.window_stream_sha256,
        }

    @property
    def receipt_sha256(self) -> str:
        return _sha256_document(self._body_document())

    def to_document(self) -> dict[str, object]:
        body = self._body_document()
        return {**body, "replay_execution_receipt_sha256": self.receipt_sha256}


@dataclass(frozen=True, slots=True)
class Day1BRepresentativeQuery:
    """Claimed private representative; never accepted as caller authority."""

    receipt: Day1BReplayExecutionReceipt
    binding: Day1BQueryExecutionBinding
    descriptor: Day1BQueryWindowAccounting
    execution: Day1BQueryLayoutExecution
    query_vector: tuple[int, ...]
    expected_output: tuple[int, ...]
    modulus: int


@dataclass(frozen=True, slots=True)
class _RepresentativePreimage:
    binding: Day1BQueryExecutionBinding
    descriptor: Day1BQueryWindowAccounting
    execution: Day1BQueryLayoutExecution
    query_vector: tuple[int, ...]
    expected_output: tuple[int, ...]
    modulus: int


@dataclass(frozen=True, slots=True)
class _ReplayCapabilityBinding:
    receipt: Day1BReplayExecutionReceipt
    representative: Day1BRepresentativeQuery


class Day1BCandidateReplayCapability:
    """Opaque single-use same-replay representative capability."""

    __slots__ = ("_binding", "_claimed", "_lock")

    def __new__(cls) -> Day1BCandidateReplayCapability:
        raise TypeError("candidate replay capabilities are replay-collector-minted")

    def __bool__(self) -> bool:
        raise TypeError("candidate replay capability is not a caller boolean")


def _live_capability_binding(
    capability: Day1BCandidateReplayCapability,
    *,
    consume: bool,
) -> _ReplayCapabilityBinding:
    if type(capability) is not Day1BCandidateReplayCapability:
        raise TypeError("candidate replay must be one exact collector-minted capability")
    lock = getattr(capability, "_lock", None)
    if type(lock) is not type(threading.Lock()):
        raise Day1BReplayExecutionError("candidate replay capability is not authoritative")
    with lock:
        if getattr(capability, "_claimed", None) is not False:
            raise Day1BReplayExecutionError(
                "candidate replay capability is absent or consumed"
            )
        if consume:
            object.__setattr__(capability, "_claimed", True)
        binding = getattr(capability, "_binding", None)
    try:
        if type(binding) is not _ReplayCapabilityBinding:
            raise Day1BReplayExecutionError(
                "candidate replay capability is not authoritative"
            )
        representative = binding.representative
        receipt = binding.receipt
        rebuilt, expected_output = _binding_for_pair(
            representative.descriptor,
            representative.execution,
            candidate_id=receipt.candidate_id,
            candidate_role=receipt.candidate_role,
            candidate_policy_sha256=receipt.candidate_policy_sha256,
            retained_phases=receipt.retained_phases,
            query_vector=representative.query_vector,
            query_vector_sha256=receipt.query_vector_sha256,
            modulus=representative.modulus,
            retain_private_bundle=True,
        )
        if expected_output is None or (
            rebuilt != representative.binding
            or expected_output != representative.expected_output
            or rebuilt.binding_sha256
            != receipt.representative_query_execution_binding_sha256
            or representative.receipt is not receipt
        ):
            raise Day1BReplayExecutionError(
                "candidate replay capability differs from its representative binding"
            )
    finally:
        if consume:
            with lock:
                object.__setattr__(capability, "_binding", None)
    return binding


def describe_day1b_candidate_replay_capability(
    capability: Day1BCandidateReplayCapability,
) -> Day1BReplayExecutionReceipt:
    """Describe a live non-authorizing replay receipt without consuming it."""

    return _live_capability_binding(capability, consume=False).receipt


def claim_day1b_candidate_replay_capability(
    capability: Day1BCandidateReplayCapability,
) -> Day1BRepresentativeQuery:
    """Consume the replay capability and return its exact private representative."""

    return _live_capability_binding(capability, consume=True).representative


def abandon_day1b_candidate_replay_capability(
    capability: Day1BCandidateReplayCapability,
) -> None:
    """Consume an unused replay capability without exposing its private carrier."""

    _live_capability_binding(capability, consume=True)


class _Day1BQueryExecutionCollector:
    """Stream all bindings and retain one canonical typed representative."""

    __slots__ = (
        "_binding_count",
        "_binding_stream_hasher",
        "_candidate_id",
        "_candidate_policy_sha256",
        "_candidate_role",
        "_descriptor_stream_hasher",
        "_finished",
        "_modulus",
        "_previous_query_end",
        "_previous_window_index",
        "_query_vector",
        "_query_vector_sha256",
        "_representative",
        "_retained_phases",
    )

    def __init__(
        self,
        *,
        candidate: RegisteredCandidate,
        query_vector_canonical_bytes: bytes,
        query_vector_sha256: str,
        modulus: int,
    ) -> None:
        if type(candidate) is not RegisteredCandidate:
            raise TypeError("candidate must be an exact RegisteredCandidate")
        candidate_document = _candidate_document(candidate)
        retained_phases: tuple[RetainedPhase, ...] = (
            ("held-out",)
            if candidate.role == "ablation"
            else ("tuning-prefix", "held-out")
        )
        if retained_phases not in _RETAINED_PHASE_SETS:
            raise Day1BReplayExecutionError(
                "retained phases must equal one frozen reference or ablation set"
            )
        if modulus != _FROZEN_PLAINTEXT_MODULUS:
            raise Day1BReplayExecutionError(
                "representative modulus must equal the frozen plaintext modulus"
            )
        self._candidate_id = candidate.candidate_id
        self._candidate_role = candidate.role
        self._candidate_policy_sha256 = _sha256_document(candidate_document)
        self._query_vector = _decode_query_vector(
            query_vector_canonical_bytes,
            query_vector_sha256,
        )
        self._query_vector_sha256 = query_vector_sha256
        self._retained_phases = retained_phases
        self._modulus = modulus
        self._descriptor_stream_hasher = hashlib.sha256()
        self._binding_stream_hasher = hashlib.sha256()
        self._binding_count = 0
        self._previous_window_index = -1
        self._previous_query_end = 0
        self._representative: _RepresentativePreimage | None = None
        self._finished = False

    def accept(
        self,
        descriptor: Day1BQueryWindowAccounting,
        execution: Day1BQueryLayoutExecution,
    ) -> None:
        if self._finished:
            raise Day1BReplayExecutionError("query execution collector is already finished")
        _require_pair(descriptor, execution)
        if (
            descriptor.window_index <= self._previous_window_index
            or descriptor.first_global_query_ordinal != self._previous_query_end
        ):
            raise Day1BReplayExecutionError(
                "query execution stream order or query ordinals are not contiguous"
            )
        retain_private_bundle = (
            self._representative is None
            and descriptor.phase == self._retained_phases[0]
        )
        binding, expected_output = _binding_for_pair(
            descriptor,
            execution,
            candidate_id=self._candidate_id,
            candidate_role=self._candidate_role,
            candidate_policy_sha256=self._candidate_policy_sha256,
            retained_phases=self._retained_phases,
            query_vector=self._query_vector,
            query_vector_sha256=self._query_vector_sha256,
            modulus=self._modulus,
            retain_private_bundle=retain_private_bundle,
        )
        self._descriptor_stream_hasher.update(
            _canonical_bytes(descriptor.to_document())
        )
        self._binding_stream_hasher.update(_canonical_bytes(binding.to_document()))
        self._binding_count += 1
        self._previous_window_index = descriptor.window_index
        self._previous_query_end = (
            descriptor.first_global_query_ordinal + descriptor.query_count
        )
        if retain_private_bundle:
            assert expected_output is not None
            self._representative = _RepresentativePreimage(
                binding=binding,
                descriptor=descriptor,
                execution=execution,
                query_vector=self._query_vector,
                expected_output=expected_output,
                modulus=self._modulus,
            )

    def finish(
        self,
        accounting: PublicationDay1BAccounting,
    ) -> Day1BCandidateReplayCapability:
        if self._finished:
            raise Day1BReplayExecutionError("query execution collector is already finished")
        self._finished = True
        if type(accounting) is not PublicationDay1BAccounting:
            raise TypeError("accounting must be one exact PublicationDay1BAccounting")
        descriptor_root = _sequence_root(
            count=self._binding_count,
            stream_sha256=self._descriptor_stream_hasher.hexdigest(),
            schema="dynamic-cssc-publication-day1b-query-window-stream-v1",
        )
        binding_root = _sequence_root(
            count=self._binding_count,
            stream_sha256=self._binding_stream_hasher.hexdigest(),
            schema=DAY1B_QUERY_EXECUTION_STREAM_SCHEMA,
        )
        representative = self._representative
        if (
            self._binding_count != accounting.realized_query_window_count
            or descriptor_root != accounting.query_window_stream_sha256
            or accounting.candidate_id != self._candidate_id
            or accounting.candidate_policy_sha256
            != self._candidate_policy_sha256
            or representative is None
            or representative.binding.phase != self._retained_phases[0]
            or accounting.state_reset_count != 0
        ):
            raise Day1BReplayExecutionError(
                "query execution stream does not close against complete accounting"
            )
        receipt = Day1BReplayExecutionReceipt(
            candidate_id=self._candidate_id,
            candidate_role=self._candidate_role,
            candidate_policy_sha256=self._candidate_policy_sha256,
            retained_phases=self._retained_phases,
            accounting_sha256=accounting.accounting_sha256,
            window_stream_sha256=accounting.window_stream_sha256,
            query_window_stream_sha256=accounting.query_window_stream_sha256,
            query_execution_binding_stream_sha256=binding_root,
            query_execution_binding_count=self._binding_count,
            query_vector_sha256=self._query_vector_sha256,
            plaintext_modulus=self._modulus,
            representative_query_execution_binding_sha256=(
                representative.binding.binding_sha256
            ),
            representative_phase=representative.binding.phase,
            representative_window_index=representative.binding.window_index,
            terminal_version_id=accounting.terminal_version_id,
            terminal_logical_state_sha256=(
                accounting.terminal_logical_state_sha256
            ),
            state_reset_count=accounting.state_reset_count,
        )
        representative = Day1BRepresentativeQuery(
            receipt=receipt,
            binding=representative.binding,
            descriptor=representative.descriptor,
            execution=representative.execution,
            query_vector=representative.query_vector,
            expected_output=representative.expected_output,
            modulus=representative.modulus,
        )
        binding = _ReplayCapabilityBinding(
            receipt=receipt,
            representative=representative,
        )
        capability = object.__new__(Day1BCandidateReplayCapability)
        object.__setattr__(capability, "_binding", binding)
        object.__setattr__(capability, "_claimed", False)
        object.__setattr__(capability, "_lock", threading.Lock())
        return capability


def replay_and_seal_publication_day1b_candidate(
    *,
    candidate: RegisteredCandidate,
    windows: Iterable[ExactPublicationWindow],
    domain: Day1BAccountingDomain,
    query_vector_canonical_bytes: bytes,
    query_vector_sha256: str,
    query_window_sink: Callable[[Day1BQueryWindowAccounting], None] | None = None,
) -> tuple[PublicationDay1BAccounting, Day1BCandidateReplayCapability]:
    """Own one exact replay call and seal its role-derived representative.

    Callers may observe the compact descriptor stream through ``query_window_sink``
    but cannot submit a typed carrier stream or a separately sourced accounting
    result.  The returned capability remains non-authorizing.
    """

    collector = _Day1BQueryExecutionCollector(
        candidate=candidate,
        query_vector_canonical_bytes=query_vector_canonical_bytes,
        query_vector_sha256=query_vector_sha256,
        modulus=_FROZEN_PLAINTEXT_MODULUS,
    )
    accounting = replay_publication_day1b_candidate_cell(
        candidate=candidate,
        windows=windows,
        domain=domain,
        query_window_sink=query_window_sink,
        query_execution_sink=collector.accept,
    )
    return accounting, collector.finish(accounting)


__all__ = (
    "DAY1B_QUERY_EXECUTION_BINDING_SCHEMA",
    "DAY1B_QUERY_EXECUTION_STREAM_SCHEMA",
    "DAY1B_REPLAY_EXECUTION_RECEIPT_SCHEMA",
    "DAY1B_REPRESENTATIVE_SELECTION_RULE",
    "Day1BCandidateReplayCapability",
    "Day1BQueryExecutionBinding",
    "Day1BReplayExecutionError",
    "Day1BReplayExecutionReceipt",
    "Day1BRepresentativeQuery",
    "abandon_day1b_candidate_replay_capability",
    "claim_day1b_candidate_replay_capability",
    "describe_day1b_candidate_replay_capability",
    "replay_and_seal_publication_day1b_candidate",
)
