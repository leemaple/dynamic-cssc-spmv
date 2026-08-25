"""Closed streaming evidence protocol for a future publication Day1B worker.

This module validates worker output; it does not locate, admit, or execute a worker.
Binary protocol-object payloads are hashed while transport chunks arrive and are never
retained in the returned receipt.  Controller scratch is supplied as launcher-opened
storage and never reopens a pathname after the capability is claimed.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import sqlite3
import stat
import tempfile
import threading
import weakref
from collections.abc import Callable, Iterable
from contextlib import suppress
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import BinaryIO

from dynamic_cssc.publication_day1b_aggregate_bounds import (
    DAY1B_AGGREGATE_RECEIPT_CANONICAL_BYTES_MAXIMUM,
)
from dynamic_cssc.publication_day1b_f1m_aggregation import (
    Day1BF1MAggregationError,
    Day1BF1MControllerContext,
    Day1BF1MRouteCoverage,
)

DAY1B_WORKER_FRAME_SCHEMA = "dynamic-cssc-publication-day1b-worker-frame-v2"
DAY1B_WORKER_INPUT_BINDING_SCHEMA = "dynamic-cssc-publication-day1b-worker-input-binding-v7"
DAY1B_WORKER_RECEIPT_SCHEMA = "dynamic-cssc-publication-day1b-worker-candidate-cell-receipt-v8"
DAY1B_WORKER_WINDOW_AUDIT_SCHEMA = "dynamic-cssc-publication-day1b-worker-window-audit-v1"
DAY1B_WORKER_F1M_BINDING_SCHEMA = "dynamic-cssc-publication-day1b-f1m-binding-receipt-v1"
DAY1B_WORKER_F1M_SIZE_CLASS_SCHEMA = "dynamic-cssc-publication-day1b-f1m-size-class-v1"
DAY1B_WORKER_F1M_WINDOW_CARDINALITY_SCHEMA = (
    "dynamic-cssc-publication-day1b-f1m-window-cardinality-v2"
)
DAY1B_WORKER_F1M_WINDOW_BATCH_SCHEMA = "dynamic-cssc-publication-day1b-f1m-window-batch-v1"
DAY1B_WORKER_EXPECTED_F1M_OBJECT_SCHEMA = (
    "dynamic-cssc-publication-day1b-controller-expected-f1m-size-class-v3"
)
DAY1B_WORKER_EXPECTED_F1M_SIZE_CLASS_SET_SCHEMA = (
    "dynamic-cssc-publication-day1b-controller-expected-f1m-size-class-set-v3"
)
DAY1B_WORKER_EXPECTED_F1M_REGISTRY_DESCRIPTOR_SCHEMA = (
    "dynamic-cssc-publication-day1b-expected-f1m-size-class-registry-descriptor-v4"
)
DAY1B_WORKER_EXECUTION_BASIS = "window-weighted-equivalence-v1"
_DAY1B_WORKER_EXPECTED_F1M_SIZE_CLASS_SUBROOT_SCHEMA = (
    "dynamic-cssc-publication-day1b-expected-f1m-size-class-subroot-v3"
)
DAY1B_WORKER_MAX_HEADER_BYTES = 16_384
if not (0 < DAY1B_AGGREGATE_RECEIPT_CANONICAL_BYTES_MAXIMUM <= DAY1B_WORKER_MAX_HEADER_BYTES):
    raise RuntimeError("aggregate receipt bound must fit one worker frame header")
DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES = (
    "query-f1m-random-mask-ciphertexts",
    "query-f1m-encrypted-zero-dummy-ciphertexts",
)

_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PHASE_NAMES = ("warmup", "tuning-prefix", "held-out")
_AUDIT_PHASE_NAMES = ("warmup", "tuning", "heldout")
_FAILURE_CODES = frozenset(
    {
        "candidate-execution-failed",
        "candidate-infeasible",
        "candidate-missing-result",
        "candidate-timeout",
        "resident-memory-limit-exceeded",
        "scratch-limit-exceeded",
        "wall-clock-limit-exceeded",
    }
)
_OUTCOME_BY_FAILURE_CODE = {
    "candidate-execution-failed": "failed",
    "candidate-infeasible": "infeasible",
    "candidate-missing-result": "missing",
    "candidate-timeout": "timeout",
    "resident-memory-limit-exceeded": "infeasible",
    "scratch-limit-exceeded": "infeasible",
    "wall-clock-limit-exceeded": "timeout",
}
_EVIDENCE_TOKEN = object()
_EXPECTED_REGISTRY_INGEST_BATCH_SIZE = 256
_ISSUED_EVIDENCE: dict[int, tuple[weakref.ReferenceType[object], object]] = {}
_ISSUED_INVOCATIONS: dict[int, tuple[weakref.ReferenceType[object], object]] = {}
_ISSUED_EXPECTED_REGISTRIES: dict[int, tuple[weakref.ReferenceType[object], object]] = {}
_ISSUED_ANONYMOUS_SCRATCH: dict[int, tuple[weakref.ReferenceType[object], object]] = {}
_EVIDENCE_LOCK = threading.Lock()
_INVOCATION_LOCK = threading.Lock()
_EXPECTED_REGISTRY_LOCK = threading.Lock()
_ANONYMOUS_SCRATCH_LOCK = threading.Lock()
_COMMON_FRAME_KEYS = frozenset({"frame_kind", "payload_byte_count", "schema_version", "sequence"})
_WORKER_INPUT_BINDING_KEYS = frozenset(
    {
        "schema_version",
        "candidate_catalog_sha256",
        "candidate",
        "ciphertext_bytes",
        "day2_outer_archive_sha256",
        "event_schedule_sha256",
        "expected_f1m_size_class_count",
        "expected_f1m_size_class_set_sha256",
        "expected_f1m_cardinality_derivation_root_sha256",
        "expected_serialized_equivalence_class_count",
        "execution_basis",
        "freshness",
        "f1m_encrypted_zero_dummy_ciphertext_bytes",
        "f1m_random_zero_sum_ciphertext_bytes",
        "f1m_size_class_categories",
        "f1m_controller_context_document",
        "f1m_controller_context_sha256",
        "f1m_route_coverage_document",
        "f1m_route_coverage_sha256",
        "f1m_charged_size_class_set_sha256",
        "phase_ranges",
        "primitive_names",
        "query_vector_sha256",
        "invocation_id",
        "resource_limits",
        "resource_policy_sha256",
        "rho",
        "serialized_object_size_profile_sha256",
        "serialized_categories",
        "trace_manifest_sha256",
    }
)
_WORKER_INPUT_CANDIDATE_KEYS = frozenset(
    {
        "candidate_id",
        "candidate_policy_digest",
        "candidate_role",
        "f1m_policy",
        "retained_phases",
        "strategy",
    }
)
_WORKER_INPUT_PHASE_RANGE_KEYS = frozenset({"phase", "accepted_group_start", "accepted_group_end"})
_FRAME_KEYS = {
    "cell-start": _COMMON_FRAME_KEYS | {"input_binding"},
    "candidate-start": _COMMON_FRAME_KEYS | {"candidate_id", "candidate_role"},
    "serialized-object": _COMMON_FRAME_KEYS
    | {
        "candidate_id",
        "category",
        "f1m_size_class",
        "multiplicity",
        "object_ordinal",
        "phase",
    },
    "phase-result": _COMMON_FRAME_KEYS
    | {
        "candidate_id",
        "failure_code",
        "outcome",
        "phase",
        "phase_audit",
        "query_primitive_counts",
        "retained_measurement",
        "serialized_category_object_counts",
        "update_primitive_counts",
    },
    "candidate-result": _COMMON_FRAME_KEYS
    | {
        "candidate_id",
        "candidate_retry_count",
        "elapsed_ns",
        "peak_resident_memory_bytes",
        "peak_scratch_bytes",
        "state_reset_count",
    },
    "cell-end": _COMMON_FRAME_KEYS | {"candidate_count"},
}


class Day1BWorkerProtocolError(ValueError):
    """The worker stream is structurally corrupt or contradicts controller facts."""


def _require_popped_authoritative_binding(
    active: tuple[weakref.ReferenceType[object], object] | None,
    *,
    capability: object,
    presented: object,
    binding_type: type[object],
    cleanup: Callable[[object], None],
    error_message: str,
) -> object:
    """Validate one popped registry entry or reclaim only its authoritative value."""

    if (
        active is not None
        and active[0]() is capability
        and active[1] is presented
        and type(presented) is binding_type
    ):
        return presented
    if active is not None and type(active[1]) is binding_type:
        try:
            cleanup(active[1])
        except BaseException as cleanup_error:
            raise Day1BWorkerProtocolError(
                f"{error_message}; authoritative resource cleanup failed"
            ) from cleanup_error
    raise Day1BWorkerProtocolError(error_message)


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
        raise Day1BWorkerProtocolError("worker protocol value is not canonical JSON") from error
    return (rendered + "\n").encode("ascii")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise Day1BWorkerProtocolError("worker frame contains duplicate JSON keys")
        result[key] = value
    return result


def _decode_header(raw: bytes) -> dict[str, object]:
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=lambda _value: (_ for _ in ()).throw(
                Day1BWorkerProtocolError("worker frame JSON numbers must be integers")
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                Day1BWorkerProtocolError("worker frame forbids non-finite JSON values")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Day1BWorkerProtocolError("worker frame header is not canonical ASCII JSON") from error
    if type(value) is not dict or _canonical_json_bytes(value) != raw:
        raise Day1BWorkerProtocolError("worker frame header is not canonical closed JSON")
    return value


def _strict_nonnegative(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        raise Day1BWorkerProtocolError(f"{field} must be a strict nonnegative integer")
    return value


def _strict_positive(value: object, field: str) -> int:
    result = _strict_nonnegative(value, field)
    if result == 0:
        raise Day1BWorkerProtocolError(f"{field} must be positive")
    return result


def _sha256(value: object, field: str) -> str:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise Day1BWorkerProtocolError(f"{field} must be a lowercase SHA-256")
    return value


def _nonempty_string(value: object, field: str) -> str:
    if type(value) is not str or not value:
        raise Day1BWorkerProtocolError(f"{field} must be a nonempty string")
    return value


def canonical_day1b_worker_window_audit_bytes(
    *,
    index: int,
    phase: str,
    accepted_group_start: int,
    accepted_group_end: int,
    start_time: Fraction,
    end_time: Fraction,
    set_count: int,
    updates: tuple[tuple[int, int, int, int], ...],
    query_count: int,
    reason: str,
) -> bytes:
    """Serialize one controller/worker shared window-consumption audit record."""

    _strict_nonnegative(index, "window.index")
    if type(phase) is not str or phase not in _AUDIT_PHASE_NAMES:
        raise Day1BWorkerProtocolError("window phase is not frozen")
    _strict_nonnegative(accepted_group_start, "window.accepted_group_start")
    if _strict_positive(accepted_group_end, "window.accepted_group_end") <= (accepted_group_start):
        raise Day1BWorkerProtocolError("window accepted-group range must be nonempty")
    if type(start_time) is not Fraction or type(end_time) is not Fraction:
        raise Day1BWorkerProtocolError("window times must be exact Fraction values")
    if end_time <= start_time:
        raise Day1BWorkerProtocolError("window start time must be strictly before end time")
    _strict_nonnegative(set_count, "window.set_count")
    _strict_nonnegative(query_count, "window.query_count")
    if type(updates) is not tuple:
        raise Day1BWorkerProtocolError("window updates must be an exact tuple")
    serialized_updates: list[dict[str, int]] = []
    for update in updates:
        if (
            type(update) is not tuple
            or len(update) != 4
            or any(type(value) is not int for value in update)
        ):
            raise Day1BWorkerProtocolError("window update audit tuple is malformed")
        row, col, before, after = update
        if row < 0 or col < 0:
            raise Day1BWorkerProtocolError("window update coordinates must be nonnegative")
        serialized_updates.append({"after": after, "before": before, "col": col, "row": row})
    _nonempty_string(reason, "window.reason")
    return _canonical_json_bytes(
        {
            "schema_version": DAY1B_WORKER_WINDOW_AUDIT_SCHEMA,
            "accepted_group_end": accepted_group_end,
            "accepted_group_start": accepted_group_start,
            "end_time": {
                "denominator": end_time.denominator,
                "numerator": end_time.numerator,
            },
            "index": index,
            "phase": phase,
            "query_count": query_count,
            "reason": reason,
            "set_count": set_count,
            "start_time": {
                "denominator": start_time.denominator,
                "numerator": start_time.numerator,
            },
            "updates": serialized_updates,
        }
    )


@dataclass(frozen=True, slots=True)
class Day1BWorkerCandidateSpec:
    candidate_id: str
    candidate_role: str
    strategy: str
    f1m_policy: str
    candidate_policy_digest: str
    retained_phases: tuple[str, ...]

    def __post_init__(self) -> None:
        _nonempty_string(self.candidate_id, "candidate_id")
        expected = {
            "reference": ("tuning-prefix", "held-out"),
            "ablation": ("held-out",),
        }
        if type(self.candidate_role) is not str or self.candidate_role not in expected:
            raise Day1BWorkerProtocolError("candidate_role must be reference or ablation")
        if (
            type(self.retained_phases) is not tuple
            or self.retained_phases != expected[self.candidate_role]
        ):
            raise Day1BWorkerProtocolError("candidate retained phases do not match its frozen role")
        _nonempty_string(self.strategy, "candidate strategy")
        _sha256(self.candidate_policy_digest, "candidate_policy_digest")
        expected_policy = (
            "uniform-random-or-zero"
            if self.strategy == "Packed-COO-Cloud-Segmented-Delta"
            else "overlap-only"
        )
        if type(self.f1m_policy) is not str or self.f1m_policy != expected_policy:
            raise Day1BWorkerProtocolError(
                "candidate F1-M policy does not match its frozen strategy"
            )

    def to_document(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "candidate_policy_digest": self.candidate_policy_digest,
            "candidate_role": self.candidate_role,
            "f1m_policy": self.f1m_policy,
            "retained_phases": list(self.retained_phases),
            "strategy": self.strategy,
        }


@dataclass(frozen=True, slots=True)
class Day1BF1MBindingReceipt:
    """One actually materialized single-query route for the no-reuse smoke path."""

    query_id: str
    version_id: str
    output_plan_digest: str
    component_id: str
    output_block_id: str
    f1m_kind: str
    ledger_commitment_token: str
    private_plan_digest: str
    execution_binding_digest: str

    def __post_init__(self) -> None:
        for field in (
            "query_id",
            "version_id",
            "component_id",
            "output_block_id",
        ):
            _nonempty_string(getattr(self, field), f"f1m_binding.{field}")
        for field in (
            "output_plan_digest",
            "ledger_commitment_token",
            "private_plan_digest",
            "execution_binding_digest",
        ):
            _sha256(getattr(self, field), f"f1m_binding.{field}")
        if type(self.f1m_kind) is not str or self.f1m_kind not in {
            "random-zero-sum",
            "encrypted-zero-dummy",
        }:
            raise Day1BWorkerProtocolError("f1m_binding kind is not frozen")

    @property
    def no_reuse_key(self) -> tuple[str, str, str, str, str]:
        return (
            self.query_id,
            self.version_id,
            self.output_plan_digest,
            self.component_id,
            self.output_block_id,
        )

    def to_document(self) -> dict[str, object]:
        return {
            "schema_version": DAY1B_WORKER_F1M_BINDING_SCHEMA,
            "component_id": self.component_id,
            "execution_binding_digest": self.execution_binding_digest,
            "f1m_kind": self.f1m_kind,
            "ledger_commitment_token": self.ledger_commitment_token,
            "output_block_id": self.output_block_id,
            "output_plan_digest": self.output_plan_digest,
            "private_plan_digest": self.private_plan_digest,
            "query_id": self.query_id,
            "version_id": self.version_id,
        }

    @classmethod
    def from_document(cls, value: object) -> Day1BF1MBindingReceipt:
        keys = {
            "schema_version",
            "component_id",
            "execution_binding_digest",
            "f1m_kind",
            "ledger_commitment_token",
            "output_block_id",
            "output_plan_digest",
            "private_plan_digest",
            "query_id",
            "version_id",
        }
        if type(value) is not dict or set(value) != keys:
            raise Day1BWorkerProtocolError("F1-M binding receipt keys are not exact")
        if value["schema_version"] != DAY1B_WORKER_F1M_BINDING_SCHEMA:
            raise Day1BWorkerProtocolError("F1-M binding receipt schema is not frozen")
        return cls(**{key: value[key] for key in keys - {"schema_version"}})


@dataclass(frozen=True, slots=True)
class Day1BF1MSizeClass:
    """Query-independent identity of one weighted serialized F1-M representative.

    The descriptor deliberately cannot name a query, ledger token, random reservation,
    or state transition.  Its multiplicity is carried by the enclosing expected-object
    descriptor and means only how many logical protocol objects have this serialized
    size in the exact controller-derived query range.
    """

    version_id: str
    output_plan_digest: str
    component_id: str
    output_block_id: str
    f1m_kind: str
    private_plan_digest: str
    execution_binding_digest: str

    def __post_init__(self) -> None:
        for field in ("version_id", "component_id", "output_block_id"):
            _nonempty_string(getattr(self, field), f"f1m_size_class.{field}")
        for field in (
            "output_plan_digest",
            "private_plan_digest",
            "execution_binding_digest",
        ):
            _sha256(getattr(self, field), f"f1m_size_class.{field}")
        if type(self.f1m_kind) is not str or self.f1m_kind not in {
            "random-zero-sum",
            "encrypted-zero-dummy",
        }:
            raise Day1BWorkerProtocolError("f1m_size_class kind is not frozen")

    def to_document(self) -> dict[str, object]:
        return {
            "schema_version": DAY1B_WORKER_F1M_SIZE_CLASS_SCHEMA,
            "component_id": self.component_id,
            "execution_binding_digest": self.execution_binding_digest,
            "f1m_kind": self.f1m_kind,
            "output_block_id": self.output_block_id,
            "output_plan_digest": self.output_plan_digest,
            "private_plan_digest": self.private_plan_digest,
            "version_id": self.version_id,
        }

    @classmethod
    def from_document(cls, value: object) -> Day1BF1MSizeClass:
        keys = {
            "schema_version",
            "component_id",
            "execution_binding_digest",
            "f1m_kind",
            "output_block_id",
            "output_plan_digest",
            "private_plan_digest",
            "version_id",
        }
        if type(value) is not dict or set(value) != keys:
            raise Day1BWorkerProtocolError("F1-M size-class keys are not exact")
        if value["schema_version"] != DAY1B_WORKER_F1M_SIZE_CLASS_SCHEMA:
            raise Day1BWorkerProtocolError("F1-M size-class schema is not frozen")
        return cls(**{key: value[key] for key in keys - {"schema_version"}})


def canonical_day1b_f1m_query_id(
    *,
    invocation_id: str,
    global_query_ordinal: int,
) -> str:
    """Derive a replay-stable query id without the circular expected-set root."""

    _sha256(invocation_id, "invocation_id")
    _strict_nonnegative(global_query_ordinal, "global_query_ordinal")
    digest = hashlib.sha256(
        _canonical_json_bytes(
            {
                "global_query_ordinal": global_query_ordinal,
                "invocation_id": invocation_id,
                "schema_version": "dynamic-cssc-day1b-query-identity-v1",
            }
        )
    ).hexdigest()
    return f"day1b-query-{digest}"


@dataclass(frozen=True, slots=True)
class Day1BF1MWindowCardinality:
    """Controller-derived OutputPlan/share cardinality for one retained window."""

    phase: str
    window_index: int
    accepted_group_start: int
    accepted_group_end: int
    first_global_query_ordinal: int
    query_count: int
    version_id: str
    output_plan_digest: str
    private_plan_digest: str
    execution_binding_digest: str
    f1m_policy: str
    returned_share_count: int
    overlap_masked_share_count: int
    expected_random_route_count: int
    expected_dummy_route_count: int
    expected_size_class_subroot_sha256: str

    def __post_init__(self) -> None:
        if type(self.phase) is not str or self.phase not in _PHASE_NAMES:
            raise Day1BWorkerProtocolError("F1-M cardinality phase is not frozen")
        _strict_nonnegative(self.window_index, "F1-M cardinality window_index")
        start = _strict_nonnegative(
            self.accepted_group_start,
            "F1-M cardinality accepted_group_start",
        )
        end = _strict_nonnegative(
            self.accepted_group_end,
            "F1-M cardinality accepted_group_end",
        )
        if end <= start:
            raise Day1BWorkerProtocolError("F1-M cardinality group range is empty")
        _strict_nonnegative(
            self.first_global_query_ordinal,
            "F1-M cardinality first_global_query_ordinal",
        )
        query_count = _strict_nonnegative(self.query_count, "F1-M cardinality query_count")
        _nonempty_string(self.version_id, "F1-M cardinality version_id")
        for field in (
            "output_plan_digest",
            "private_plan_digest",
            "execution_binding_digest",
            "expected_size_class_subroot_sha256",
        ):
            _sha256(getattr(self, field), f"F1-M cardinality {field}")
        if type(self.f1m_policy) is not str or self.f1m_policy not in {
            "overlap-only",
            "uniform-random-or-zero",
        }:
            raise Day1BWorkerProtocolError("F1-M cardinality policy is not frozen")
        returned = _strict_nonnegative(
            self.returned_share_count,
            "F1-M cardinality returned_share_count",
        )
        masked = _strict_nonnegative(
            self.overlap_masked_share_count,
            "F1-M cardinality overlap_masked_share_count",
        )
        if masked > returned:
            raise Day1BWorkerProtocolError(
                "F1-M overlap-masked share count exceeds returned shares"
            )
        expected_random = query_count * masked
        expected_dummy = (
            0 if self.f1m_policy == "overlap-only" else query_count * (returned - masked)
        )
        if (
            _strict_nonnegative(
                self.expected_random_route_count,
                "F1-M cardinality expected_random_route_count",
            )
            != expected_random
            or _strict_nonnegative(
                self.expected_dummy_route_count,
                "F1-M cardinality expected_dummy_route_count",
            )
            != expected_dummy
        ):
            raise Day1BWorkerProtocolError(
                "F1-M route cardinality does not match query count and unique OutputShares"
            )

    def to_document(self) -> dict[str, object]:
        return {
            "accepted_group_end": self.accepted_group_end,
            "accepted_group_start": self.accepted_group_start,
            "execution_binding_digest": self.execution_binding_digest,
            "expected_dummy_route_count": self.expected_dummy_route_count,
            "expected_random_route_count": self.expected_random_route_count,
            "expected_size_class_subroot_sha256": self.expected_size_class_subroot_sha256,
            "f1m_policy": self.f1m_policy,
            "first_global_query_ordinal": self.first_global_query_ordinal,
            "output_plan_digest": self.output_plan_digest,
            "overlap_masked_share_count": self.overlap_masked_share_count,
            "phase": self.phase,
            "private_plan_digest": self.private_plan_digest,
            "query_count": self.query_count,
            "returned_share_count": self.returned_share_count,
            "schema_version": DAY1B_WORKER_F1M_WINDOW_CARDINALITY_SCHEMA,
            "version_id": self.version_id,
            "window_index": self.window_index,
        }


@dataclass(frozen=True, slots=True)
class Day1BF1MWindowBatch:
    """One query-bearing window range paired with its weighted size classes."""

    phase: str
    window_index: int
    first_global_query_ordinal: int
    query_count: int
    version_id: str
    output_plan_digest: str
    private_plan_digest: str
    execution_binding_digest: str
    size_class_subroot_sha256: str

    def __post_init__(self) -> None:
        if type(self.phase) is not str or self.phase not in _PHASE_NAMES:
            raise Day1BWorkerProtocolError("F1-M window batch phase is not frozen")
        _strict_nonnegative(self.window_index, "F1-M window batch window_index")
        _strict_nonnegative(
            self.first_global_query_ordinal,
            "F1-M window batch first_global_query_ordinal",
        )
        _strict_positive(self.query_count, "F1-M window batch query_count")
        _nonempty_string(self.version_id, "F1-M window batch version_id")
        for field in (
            "output_plan_digest",
            "private_plan_digest",
            "execution_binding_digest",
            "size_class_subroot_sha256",
        ):
            _sha256(getattr(self, field), f"F1-M window batch {field}")

    def to_document(self) -> dict[str, object]:
        return {
            "execution_binding_digest": self.execution_binding_digest,
            "first_global_query_ordinal": self.first_global_query_ordinal,
            "output_plan_digest": self.output_plan_digest,
            "phase": self.phase,
            "private_plan_digest": self.private_plan_digest,
            "query_count": self.query_count,
            "schema_version": DAY1B_WORKER_F1M_WINDOW_BATCH_SCHEMA,
            "size_class_subroot_sha256": self.size_class_subroot_sha256,
            "version_id": self.version_id,
            "window_index": self.window_index,
        }


@dataclass(frozen=True, slots=True)
class Day1BControllerExpectedF1MObject:
    """One controller-derived weighted F1-M serialized size class."""

    phase: str
    window_index: int
    first_global_query_ordinal: int
    category: str
    object_ordinal: int
    f1m_size_class: Day1BF1MSizeClass
    multiplicity: int = 1

    def __post_init__(self) -> None:
        if type(self.phase) is not str or self.phase not in _PHASE_NAMES:
            raise Day1BWorkerProtocolError("expected F1-M phase is not frozen")
        if (
            type(self.category) is not str
            or self.category not in DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES
        ):
            raise Day1BWorkerProtocolError("expected F1-M category is not frozen")
        _strict_nonnegative(self.window_index, "expected F1-M window_index")
        _strict_nonnegative(
            self.first_global_query_ordinal,
            "expected F1-M first_global_query_ordinal",
        )
        _strict_nonnegative(self.object_ordinal, "expected F1-M object ordinal")
        _strict_positive(self.multiplicity, "expected F1-M object multiplicity")
        if type(self.f1m_size_class) is not Day1BF1MSizeClass:
            raise Day1BWorkerProtocolError("expected F1-M size-class type is not exact")
        expected_kind = {
            "query-f1m-random-mask-ciphertexts": "random-zero-sum",
            "query-f1m-encrypted-zero-dummy-ciphertexts": "encrypted-zero-dummy",
        }[self.category]
        if self.f1m_size_class.f1m_kind != expected_kind:
            raise Day1BWorkerProtocolError("expected F1-M category/kind size class changed")

    @property
    def size_class_key(self) -> tuple[str, int, str, int]:
        return self.phase, self.window_index, self.category, self.object_ordinal

    def to_document(self) -> dict[str, object]:
        return {
            "schema_version": DAY1B_WORKER_EXPECTED_F1M_OBJECT_SCHEMA,
            "category": self.category,
            "f1m_size_class": self.f1m_size_class.to_document(),
            "first_global_query_ordinal": self.first_global_query_ordinal,
            "multiplicity": self.multiplicity,
            "object_ordinal": self.object_ordinal,
            "phase": self.phase,
            "window_index": self.window_index,
        }

    @classmethod
    def from_document(cls, value: object) -> Day1BControllerExpectedF1MObject:
        keys = {
            "schema_version",
            "category",
            "f1m_size_class",
            "first_global_query_ordinal",
            "multiplicity",
            "object_ordinal",
            "phase",
            "window_index",
        }
        if type(value) is not dict or set(value) != keys:
            raise Day1BWorkerProtocolError("expected F1-M object keys are not exact")
        if value["schema_version"] != DAY1B_WORKER_EXPECTED_F1M_OBJECT_SCHEMA:
            raise Day1BWorkerProtocolError("expected F1-M object schema is not frozen")
        try:
            return cls(
                phase=value["phase"],
                window_index=value["window_index"],
                first_global_query_ordinal=value["first_global_query_ordinal"],
                multiplicity=value["multiplicity"],
                category=value["category"],
                object_ordinal=value["object_ordinal"],
                f1m_size_class=Day1BF1MSizeClass.from_document(value["f1m_size_class"]),
            )
        except (KeyError, TypeError) as error:  # pragma: no cover - closed keys above
            raise Day1BWorkerProtocolError("expected F1-M object is malformed") from error


def _validate_expected_f1m_objects(
    value: tuple[Day1BControllerExpectedF1MObject, ...],
) -> None:
    if type(value) is not tuple or any(
        type(item) is not Day1BControllerExpectedF1MObject for item in value
    ):
        raise Day1BWorkerProtocolError("expected F1-M objects must be an exact tuple")
    phase_order = {phase: index for index, phase in enumerate(_PHASE_NAMES)}
    category_order = {
        category: index
        for index, category in enumerate(DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES)
    }
    previous_order: tuple[int, int, int, int] | None = None
    for item in value:
        order = _expected_f1m_order(item, phase_order, category_order)
        if previous_order is not None and order <= previous_order:
            raise Day1BWorkerProtocolError(
                "expected F1-M size classes must be unique and in canonical order"
            )
        previous_order = order


def _expected_f1m_order(
    item: Day1BControllerExpectedF1MObject,
    phase_order: dict[str, int],
    category_order: dict[str, int],
) -> tuple[int, int, int, int]:
    if type(item) is not Day1BControllerExpectedF1MObject:
        raise Day1BWorkerProtocolError("expected F1-M stream contains a non-exact descriptor")
    return (
        phase_order[item.phase],
        item.window_index,
        item.object_ordinal,
        category_order[item.category],
    )


def canonical_day1b_expected_f1m_size_class_set_sha256(
    expected: tuple[Day1BControllerExpectedF1MObject, ...],
) -> str:
    """Hash the exact controller expected weighted size-class set."""

    _validate_expected_f1m_objects(expected)
    hasher = hashlib.sha256()
    hasher.update(b'{"objects":[')
    for index, item in enumerate(expected):
        if index:
            hasher.update(b",")
        hasher.update(_canonical_json_bytes(item.to_document())[:-1])
    hasher.update(
        b'],"schema_version":'
        + json.dumps(DAY1B_WORKER_EXPECTED_F1M_SIZE_CLASS_SET_SCHEMA).encode("ascii")
        + b"}\n"
    )
    return hasher.hexdigest()


def canonical_day1b_expected_f1m_size_class_subroot_sha256(
    routes: tuple[Day1BControllerExpectedF1MObject, ...],
) -> str:
    """Hash one canonical size-class subset used by a retained window."""

    _validate_expected_f1m_objects(routes)
    hasher = hashlib.sha256()
    hasher.update(b'{"routes":[')
    for index, item in enumerate(routes):
        if index:
            hasher.update(b",")
        hasher.update(_canonical_json_bytes(item.to_document())[:-1])
    hasher.update(
        b'],"schema_version":'
        + json.dumps(_DAY1B_WORKER_EXPECTED_F1M_SIZE_CLASS_SUBROOT_SCHEMA).encode("ascii")
        + b"}\n"
    )
    return hasher.hexdigest()


def canonical_day1b_f1m_cardinality_derivation_root_sha256(
    *,
    window_cardinalities: tuple[Day1BF1MWindowCardinality, ...],
    window_batches: tuple[Day1BF1MWindowBatch, ...],
    expected_size_classes: tuple[Day1BControllerExpectedF1MObject, ...],
) -> str:
    """Hash the closed window/range/size-class derivation."""

    if type(window_cardinalities) is not tuple or any(
        type(row) is not Day1BF1MWindowCardinality for row in window_cardinalities
    ):
        raise Day1BWorkerProtocolError("window cardinalities must be an exact tuple")
    if type(window_batches) is not tuple or any(
        type(row) is not Day1BF1MWindowBatch for row in window_batches
    ):
        raise Day1BWorkerProtocolError("window batches must be an exact tuple")
    _validate_expected_f1m_objects(expected_size_classes)

    window_hasher = hashlib.sha256()
    window_hasher.update(b'{"windows":[')
    for index, row in enumerate(window_cardinalities):
        if index:
            window_hasher.update(b",")
        window_hasher.update(_canonical_json_bytes(row.to_document())[:-1])
    window_hasher.update(
        b'],"schema_version":"dynamic-cssc-day1b-f1m-window-cardinality-set-v3"}\n'
    )

    window_batch_hasher = hashlib.sha256()
    window_batch_hasher.update(b'{"window_batches":[')
    for index, row in enumerate(window_batches):
        if index:
            window_batch_hasher.update(b",")
        window_batch_hasher.update(_canonical_json_bytes(row.to_document())[:-1])
    window_batch_hasher.update(
        b'],"schema_version":"dynamic-cssc-day1b-f1m-window-batch-set-v1"}\n'
    )
    return hashlib.sha256(
        _canonical_json_bytes(
            {
                "window_batch_stream_sha256": window_batch_hasher.hexdigest(),
                "size_class_set_sha256": (
                    canonical_day1b_expected_f1m_size_class_set_sha256(expected_size_classes)
                ),
                "schema_version": "dynamic-cssc-day1b-f1m-cardinality-derivation-v4",
                "window_cardinality_stream_sha256": window_hasher.hexdigest(),
            }
        )
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class Day1BWorkerPhaseRange:
    phase: str
    accepted_group_start: int
    accepted_group_end: int

    def __post_init__(self) -> None:
        if type(self.phase) is not str or self.phase not in _AUDIT_PHASE_NAMES:
            raise Day1BWorkerProtocolError("worker phase range name is not frozen")
        start = _strict_nonnegative(self.accepted_group_start, "accepted_group_start")
        end = _strict_nonnegative(self.accepted_group_end, "accepted_group_end")
        if end <= start:
            raise Day1BWorkerProtocolError("worker phase range must be nonempty")

    def to_document(self) -> dict[str, object]:
        return {
            "phase": self.phase,
            "accepted_group_start": self.accepted_group_start,
            "accepted_group_end": self.accepted_group_end,
        }


@dataclass(frozen=True, slots=True)
class Day1BWorkerPhaseAudit:
    phase: str
    accepted_group_start: int
    accepted_group_end: int
    realized_window_count: int
    realized_set_count: int
    realized_query_count: int
    consumed_window_audit_stream_sha256: str

    def __post_init__(self) -> None:
        Day1BWorkerPhaseRange(
            self.phase,
            self.accepted_group_start,
            self.accepted_group_end,
        )
        _strict_positive(self.realized_window_count, "realized_window_count")
        _strict_nonnegative(self.realized_set_count, "realized_set_count")
        _strict_nonnegative(self.realized_query_count, "realized_query_count")
        _sha256(
            self.consumed_window_audit_stream_sha256,
            "consumed_window_audit_stream_sha256",
        )

    def to_document(self) -> dict[str, object]:
        return {
            "accepted_group_end": self.accepted_group_end,
            "accepted_group_start": self.accepted_group_start,
            "consumed_window_audit_stream_sha256": (self.consumed_window_audit_stream_sha256),
            "phase": self.phase,
            "realized_query_count": self.realized_query_count,
            "realized_set_count": self.realized_set_count,
            "realized_window_count": self.realized_window_count,
        }

    @classmethod
    def from_document(cls, value: object) -> Day1BWorkerPhaseAudit:
        keys = {
            "accepted_group_end",
            "accepted_group_start",
            "consumed_window_audit_stream_sha256",
            "phase",
            "realized_query_count",
            "realized_set_count",
            "realized_window_count",
        }
        if type(value) is not dict or set(value) != keys:
            raise Day1BWorkerProtocolError("worker phase audit keys are not exact")
        return cls(**value)


@dataclass(frozen=True, slots=True)
class _ControllerCandidateObservation:
    """Launcher-owned process observations for one candidate/cell execution.

    ``peak_scratch_bytes`` is candidate-execution scratch governed by
    ``scratch_bytes_per_candidate_cell``.  It is not the registry/spool peak
    maintained by :class:`_ControlledScratch`.
    """

    candidate_id: str
    elapsed_ns: int
    peak_resident_memory_bytes: int
    peak_scratch_bytes: int
    terminal_failure_code: str | None

    def __post_init__(self) -> None:
        _nonempty_string(self.candidate_id, "controller observation candidate_id")
        _strict_nonnegative(self.elapsed_ns, "controller observation elapsed_ns")
        _strict_nonnegative(
            self.peak_resident_memory_bytes,
            "controller observation peak_resident_memory_bytes",
        )
        _strict_nonnegative(
            self.peak_scratch_bytes,
            "controller observation peak_scratch_bytes",
        )
        if self.terminal_failure_code is not None and (
            type(self.terminal_failure_code) is not str
            or self.terminal_failure_code not in _FAILURE_CODES
        ):
            raise Day1BWorkerProtocolError(
                "controller observation terminal failure code is not frozen"
            )


@dataclass(frozen=True, slots=True)
class Day1BWorkerResourceLimits:
    wall_clock_ns_per_candidate_cell: int
    resident_memory_bytes_per_candidate_cell: int
    scratch_bytes_per_candidate_cell: int
    serialized_object_bytes_maximum: int
    serialized_object_receipt_count_maximum: int
    serialized_object_receipt_spool_bytes_maximum: int
    serialized_payload_bytes_per_cell_maximum: int
    worker_frame_count_maximum: int
    controller_registered_scratch_bytes_checkpoint_maximum: int

    def __post_init__(self) -> None:
        for field in self.__dataclass_fields__:
            _strict_positive(getattr(self, field), f"resource_limits.{field}")

    def to_document(self) -> dict[str, object]:
        return {field: getattr(self, field) for field in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class Day1BWorkerProtocolContract:
    invocation_id: str
    trace_manifest_sha256: str
    event_schedule_sha256: str
    query_vector_sha256: str
    candidate_catalog_sha256: str
    resource_policy_sha256: str
    day2_outer_archive_sha256: str
    serialized_object_size_profile_sha256: str
    ciphertext_bytes: int
    f1m_random_zero_sum_ciphertext_bytes: int
    f1m_encrypted_zero_dummy_ciphertext_bytes: int
    freshness: str
    rho: str
    execution_basis: str
    candidate: Day1BWorkerCandidateSpec
    phase_ranges: tuple[Day1BWorkerPhaseRange, ...]
    primitive_names: tuple[str, ...]
    serialized_categories: tuple[tuple[str, str], ...]
    f1m_size_class_categories: tuple[str, ...]
    f1m_controller_context: Day1BF1MControllerContext
    f1m_controller_context_sha256: str
    f1m_route_coverage: Day1BF1MRouteCoverage
    f1m_route_coverage_sha256: str
    f1m_charged_size_class_set_sha256: str
    expected_f1m_size_class_set_sha256: str
    expected_f1m_size_class_count: int
    expected_serialized_equivalence_class_count: int
    expected_f1m_cardinality_derivation_root_sha256: str
    resource_limits: Day1BWorkerResourceLimits

    def __post_init__(self) -> None:
        for field in (
            "trace_manifest_sha256",
            "event_schedule_sha256",
            "query_vector_sha256",
            "candidate_catalog_sha256",
            "resource_policy_sha256",
            "day2_outer_archive_sha256",
            "serialized_object_size_profile_sha256",
            "invocation_id",
            "f1m_controller_context_sha256",
            "f1m_route_coverage_sha256",
            "f1m_charged_size_class_set_sha256",
            "expected_f1m_size_class_set_sha256",
            "expected_f1m_cardinality_derivation_root_sha256",
        ):
            _sha256(getattr(self, field), field)
        _nonempty_string(self.freshness, "freshness")
        _nonempty_string(self.rho, "rho")
        if self.execution_basis != DAY1B_WORKER_EXECUTION_BASIS:
            raise Day1BWorkerProtocolError(
                "Day1B must use the frozen window-weighted execution basis"
            )
        if type(self.candidate) is not Day1BWorkerCandidateSpec:
            raise Day1BWorkerProtocolError(
                "candidate must be one exact typed candidate-cell identity"
            )
        if (
            type(self.f1m_controller_context) is not Day1BF1MControllerContext
            or type(self.f1m_route_coverage) is not Day1BF1MRouteCoverage
        ):
            raise Day1BWorkerProtocolError(
                "F1-M controller context and route coverage must be exact typed preimages"
            )
        context = self.f1m_controller_context
        coverage = self.f1m_route_coverage
        if (
            context.context_sha256 != self.f1m_controller_context_sha256
            or coverage.route_coverage_sha256 != self.f1m_route_coverage_sha256
            or coverage.controller_context_sha256 != context.context_sha256
            or coverage.day2_outer_archive_sha256 != self.day2_outer_archive_sha256
            or coverage.serialized_object_size_profile_sha256
            != self.serialized_object_size_profile_sha256
            or coverage.element_count != context.query_window_count
            or coverage.phase_query_counts != context.phase_query_counts
            or any(
                query_windows > all_windows
                for query_windows, all_windows in zip(
                    coverage.phase_query_window_counts,
                    context.phase_window_counts,
                    strict=True,
                )
            )
            or context.trace_manifest_sha256 != self.trace_manifest_sha256
            or context.event_schedule_sha256 != self.event_schedule_sha256
            or context.query_vector_sha256 != self.query_vector_sha256
            or context.candidate_catalog_sha256 != self.candidate_catalog_sha256
            or context.resource_policy_sha256 != self.resource_policy_sha256
            or context.freshness != self.freshness
            or context.rho != self.rho
            or context.candidate_id != self.candidate.candidate_id
            or context.candidate_role != self.candidate.candidate_role
            or context.candidate_policy_sha256 != self.candidate.candidate_policy_digest
            or context.retained_phases != self.candidate.retained_phases
        ):
            raise Day1BWorkerProtocolError(
                "F1-M retained preimages retarget the worker input-binding facts"
            )
        if (
            type(self.phase_ranges) is not tuple
            or tuple(item.phase for item in self.phase_ranges) != _AUDIT_PHASE_NAMES
            or any(type(item) is not Day1BWorkerPhaseRange for item in self.phase_ranges)
        ):
            raise Day1BWorkerProtocolError("phase_ranges must be exact warmup/tuning/heldout")
        if self.phase_ranges[0].accepted_group_start != 0 or any(
            before.accepted_group_end != after.accepted_group_start
            for before, after in zip(self.phase_ranges, self.phase_ranges[1:], strict=False)
        ):
            raise Day1BWorkerProtocolError("phase_ranges must be contiguous from zero")
        if (
            type(self.primitive_names) is not tuple
            or not self.primitive_names
            or any(type(name) is not str or not name for name in self.primitive_names)
        ):
            raise Day1BWorkerProtocolError("primitive_names must be an exact nonempty tuple")
        if len(self.primitive_names) != len(set(self.primitive_names)):
            raise Day1BWorkerProtocolError("primitive_names must be unique")
        if type(self.serialized_categories) is not tuple or not self.serialized_categories:
            raise Day1BWorkerProtocolError("serialized_categories must be a nonempty tuple")
        category_names: list[str] = []
        for item in self.serialized_categories:
            if (
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or not item[0]
                or type(item[1]) is not str
                or item[1] not in {"update", "query", "one-time"}
            ):
                raise Day1BWorkerProtocolError("serialized category contract is malformed")
            category_names.append(item[0])
        if len(category_names) != len(set(category_names)):
            raise Day1BWorkerProtocolError("serialized category names must be unique")
        if (
            type(self.f1m_size_class_categories) is not tuple
            or any(type(category) is not str for category in self.f1m_size_class_categories)
            or len(self.f1m_size_class_categories) != len(set(self.f1m_size_class_categories))
            or not set(self.f1m_size_class_categories) <= set(category_names)
        ):
            raise Day1BWorkerProtocolError(
                "F1-M size-class categories must be an exact serialized-category subset"
            )
        if (
            tuple(
                category
                for category in category_names
                if category in self.f1m_size_class_categories
            )
            != self.f1m_size_class_categories
        ):
            raise Day1BWorkerProtocolError(
                "F1-M size-class categories must follow serialized category order"
            )
        if not set(DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES) <= set(category_names):
            raise Day1BWorkerProtocolError(
                "required F1-M ciphertext category set is absent from the contract"
            )
        if not set(DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES) <= set(
            self.f1m_size_class_categories
        ):
            raise Day1BWorkerProtocolError(
                "required F1-M ciphertext categories must carry size-class descriptors"
            )
        expected_f1m_count = _strict_nonnegative(
            self.expected_f1m_size_class_count,
            "expected_f1m_size_class_count",
        )
        expected_all_count = _strict_nonnegative(
            self.expected_serialized_equivalence_class_count,
            "expected_serialized_equivalence_class_count",
        )
        if expected_all_count < expected_f1m_count:
            raise Day1BWorkerProtocolError(
                "all serialized equivalence classes cannot be fewer than F1-M size classes"
            )
        if type(self.resource_limits) is not Day1BWorkerResourceLimits:
            raise Day1BWorkerProtocolError("resource_limits must be exact typed limits")
        for field in (
            "ciphertext_bytes",
            "f1m_random_zero_sum_ciphertext_bytes",
            "f1m_encrypted_zero_dummy_ciphertext_bytes",
        ):
            object_bytes = _strict_positive(getattr(self, field), field)
            if object_bytes > self.resource_limits.serialized_object_bytes_maximum:
                raise Day1BWorkerProtocolError(
                    f"anchored {field} exceeds the serialized-object cap"
                )

    def input_binding_document(self) -> dict[str, object]:
        return {
            "schema_version": DAY1B_WORKER_INPUT_BINDING_SCHEMA,
            "candidate_catalog_sha256": self.candidate_catalog_sha256,
            "candidate": self.candidate.to_document(),
            "ciphertext_bytes": self.ciphertext_bytes,
            "day2_outer_archive_sha256": self.day2_outer_archive_sha256,
            "event_schedule_sha256": self.event_schedule_sha256,
            "expected_f1m_size_class_count": self.expected_f1m_size_class_count,
            "expected_f1m_size_class_set_sha256": (self.expected_f1m_size_class_set_sha256),
            "expected_f1m_cardinality_derivation_root_sha256": (
                self.expected_f1m_cardinality_derivation_root_sha256
            ),
            "expected_serialized_equivalence_class_count": (
                self.expected_serialized_equivalence_class_count
            ),
            "execution_basis": self.execution_basis,
            "freshness": self.freshness,
            "f1m_encrypted_zero_dummy_ciphertext_bytes": (
                self.f1m_encrypted_zero_dummy_ciphertext_bytes
            ),
            "f1m_random_zero_sum_ciphertext_bytes": (self.f1m_random_zero_sum_ciphertext_bytes),
            "f1m_size_class_categories": list(self.f1m_size_class_categories),
            "f1m_controller_context_document": self.f1m_controller_context.to_document(),
            "f1m_controller_context_sha256": self.f1m_controller_context_sha256,
            "f1m_route_coverage_document": self.f1m_route_coverage.to_document(),
            "f1m_route_coverage_sha256": self.f1m_route_coverage_sha256,
            "f1m_charged_size_class_set_sha256": (self.f1m_charged_size_class_set_sha256),
            "phase_ranges": [phase.to_document() for phase in self.phase_ranges],
            "primitive_names": list(self.primitive_names),
            "query_vector_sha256": self.query_vector_sha256,
            "invocation_id": self.invocation_id,
            "resource_limits": self.resource_limits.to_document(),
            "resource_policy_sha256": self.resource_policy_sha256,
            "rho": self.rho,
            "serialized_object_size_profile_sha256": (self.serialized_object_size_profile_sha256),
            "serialized_categories": [list(item) for item in self.serialized_categories],
            "trace_manifest_sha256": self.trace_manifest_sha256,
        }

    @classmethod
    def from_input_binding_document(
        cls,
        value: object,
    ) -> Day1BWorkerProtocolContract:
        """Open one exact canonical worker input-binding preimage."""

        if type(value) is not dict or set(value) != _WORKER_INPUT_BINDING_KEYS:
            raise Day1BWorkerProtocolError("worker input-binding document keys are not exact")
        if value["schema_version"] != DAY1B_WORKER_INPUT_BINDING_SCHEMA:
            raise Day1BWorkerProtocolError("worker input-binding schema changed")
        candidate = value["candidate"]
        if type(candidate) is not dict or set(candidate) != _WORKER_INPUT_CANDIDATE_KEYS:
            raise Day1BWorkerProtocolError("worker input-binding candidate keys are not exact")
        retained_phases = candidate["retained_phases"]
        if type(retained_phases) is not list:
            raise Day1BWorkerProtocolError(
                "worker input-binding retained phases are not an exact list"
            )
        phase_ranges = value["phase_ranges"]
        if (
            type(phase_ranges) is not list
            or len(phase_ranges) != len(_AUDIT_PHASE_NAMES)
            or any(
                type(item) is not dict or set(item) != _WORKER_INPUT_PHASE_RANGE_KEYS
                for item in phase_ranges
            )
        ):
            raise Day1BWorkerProtocolError("worker input-binding phase ranges are not exact")
        primitive_names = value["primitive_names"]
        f1m_categories = value["f1m_size_class_categories"]
        serialized_categories = value["serialized_categories"]
        if type(primitive_names) is not list or type(f1m_categories) is not list:
            raise Day1BWorkerProtocolError(
                "worker input-binding tuple projections are not exact lists"
            )
        if type(serialized_categories) is not list or any(
            type(item) is not list or len(item) != 2 for item in serialized_categories
        ):
            raise Day1BWorkerProtocolError(
                "worker input-binding serialized categories are not exact"
            )
        resource_limits = value["resource_limits"]
        if type(resource_limits) is not dict or set(resource_limits) != set(
            Day1BWorkerResourceLimits.__dataclass_fields__
        ):
            raise Day1BWorkerProtocolError("worker input-binding resource-limit keys are not exact")
        try:
            f1m_controller_context = Day1BF1MControllerContext.from_document(
                value["f1m_controller_context_document"]
            )
            f1m_route_coverage = Day1BF1MRouteCoverage.from_document(
                value["f1m_route_coverage_document"]
            )
        except Day1BF1MAggregationError as error:
            raise Day1BWorkerProtocolError(
                "worker input-binding F1-M retained preimages are malformed"
            ) from error
        contract = cls(
            invocation_id=value["invocation_id"],
            trace_manifest_sha256=value["trace_manifest_sha256"],
            event_schedule_sha256=value["event_schedule_sha256"],
            query_vector_sha256=value["query_vector_sha256"],
            candidate_catalog_sha256=value["candidate_catalog_sha256"],
            resource_policy_sha256=value["resource_policy_sha256"],
            day2_outer_archive_sha256=value["day2_outer_archive_sha256"],
            serialized_object_size_profile_sha256=(value["serialized_object_size_profile_sha256"]),
            ciphertext_bytes=value["ciphertext_bytes"],
            f1m_random_zero_sum_ciphertext_bytes=(value["f1m_random_zero_sum_ciphertext_bytes"]),
            f1m_encrypted_zero_dummy_ciphertext_bytes=(
                value["f1m_encrypted_zero_dummy_ciphertext_bytes"]
            ),
            freshness=value["freshness"],
            rho=value["rho"],
            execution_basis=value["execution_basis"],
            candidate=Day1BWorkerCandidateSpec(
                candidate_id=candidate["candidate_id"],
                candidate_role=candidate["candidate_role"],
                strategy=candidate["strategy"],
                f1m_policy=candidate["f1m_policy"],
                candidate_policy_digest=candidate["candidate_policy_digest"],
                retained_phases=tuple(retained_phases),
            ),
            phase_ranges=tuple(
                Day1BWorkerPhaseRange(
                    phase=item["phase"],
                    accepted_group_start=item["accepted_group_start"],
                    accepted_group_end=item["accepted_group_end"],
                )
                for item in phase_ranges
            ),
            primitive_names=tuple(primitive_names),
            serialized_categories=tuple(tuple(item) for item in serialized_categories),
            f1m_size_class_categories=tuple(f1m_categories),
            f1m_controller_context=f1m_controller_context,
            f1m_controller_context_sha256=value["f1m_controller_context_sha256"],
            f1m_route_coverage=f1m_route_coverage,
            f1m_route_coverage_sha256=value["f1m_route_coverage_sha256"],
            f1m_charged_size_class_set_sha256=(value["f1m_charged_size_class_set_sha256"]),
            expected_f1m_size_class_set_sha256=(value["expected_f1m_size_class_set_sha256"]),
            expected_f1m_size_class_count=value["expected_f1m_size_class_count"],
            expected_serialized_equivalence_class_count=(
                value["expected_serialized_equivalence_class_count"]
            ),
            expected_f1m_cardinality_derivation_root_sha256=(
                value["expected_f1m_cardinality_derivation_root_sha256"]
            ),
            resource_limits=Day1BWorkerResourceLimits(**resource_limits),
        )
        if contract.input_binding_document() != value:
            raise Day1BWorkerProtocolError(
                "worker input-binding document is not its exact typed projection"
            )
        return contract

    @property
    def input_binding_sha256(self) -> str:
        return hashlib.sha256(_canonical_json_bytes(self.input_binding_document())).hexdigest()


def _pre_dispatch_context_sha256(
    contract: Day1BWorkerProtocolContract,
    controller_phase_audits: tuple[Day1BWorkerPhaseAudit, ...],
) -> str:
    """Bind one registry to the complete candidate-cell controller context."""

    if type(contract) is not Day1BWorkerProtocolContract:
        raise TypeError("contract must be an exact Day1BWorkerProtocolContract")
    _validate_controller_phase_audits(contract, controller_phase_audits)
    return hashlib.sha256(
        _canonical_json_bytes(
            {
                "contract_input_binding_sha256": contract.input_binding_sha256,
                "controller_phase_audits": [
                    audit.to_document() for audit in controller_phase_audits
                ],
                "schema_version": "dynamic-cssc-day1b-pre-dispatch-context-v1",
            }
        )
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class _Day1BWorkerSerializedObjectReceipt:
    serialization_equivalence_class_ordinal: int
    serialized_byte_count: int
    serialized_sha256: str
    multiplicity: int
    charged_byte_count: int
    f1m_size_class: Day1BF1MSizeClass | None

    def to_document(self) -> dict[str, object]:
        return {
            "charged_byte_count": self.charged_byte_count,
            "f1m_size_class": (
                None if self.f1m_size_class is None else self.f1m_size_class.to_document()
            ),
            "multiplicity": self.multiplicity,
            "serialization_equivalence_class_ordinal": (
                self.serialization_equivalence_class_ordinal
            ),
            "serialized_byte_count": self.serialized_byte_count,
            "serialized_sha256": self.serialized_sha256,
        }


@dataclass(frozen=True, slots=True)
class Day1BWorkerSerializedCategoryReceipt:
    category: str
    transaction: str
    serialization_equivalence_class_count: int
    protocol_object_count: int
    charged_byte_count: int
    object_receipt_stream_sha256: str
    object_receipt_spool_start_line: int
    object_receipt_spool_line_count: int

    def to_document(self) -> dict[str, object]:
        return {
            "category": self.category,
            "charged_byte_count": self.charged_byte_count,
            "object_receipt_spool_line_count": self.object_receipt_spool_line_count,
            "object_receipt_spool_start_line": self.object_receipt_spool_start_line,
            "object_receipt_stream_sha256": self.object_receipt_stream_sha256,
            "protocol_object_count": self.protocol_object_count,
            "serialization_equivalence_class_count": (self.serialization_equivalence_class_count),
            "transaction": self.transaction,
        }


@dataclass(frozen=True, slots=True)
class Day1BWorkerPhaseReceipt:
    phase: str
    retained_measurement: bool
    outcome: str
    failure_code: str | None
    update_primitive_counts: tuple[int, ...] | None
    query_primitive_counts: tuple[int, ...] | None
    serialized_categories: tuple[Day1BWorkerSerializedCategoryReceipt, ...] | None
    worker_declared_phase_audit: Day1BWorkerPhaseAudit | None

    def to_document(self) -> dict[str, object]:
        return {
            "failure_code": self.failure_code,
            "outcome": self.outcome,
            "phase": self.phase,
            "worker_declared_phase_audit": (
                None
                if self.worker_declared_phase_audit is None
                else self.worker_declared_phase_audit.to_document()
            ),
            "query_primitive_counts": (
                None if self.query_primitive_counts is None else list(self.query_primitive_counts)
            ),
            "retained_measurement": self.retained_measurement,
            "serialized_categories": (
                None
                if self.serialized_categories is None
                else [item.to_document() for item in self.serialized_categories]
            ),
            "update_primitive_counts": (
                None if self.update_primitive_counts is None else list(self.update_primitive_counts)
            ),
        }


@dataclass(frozen=True, slots=True)
class Day1BWorkerCandidateReceipt:
    candidate_id: str
    candidate_role: str
    phases: tuple[Day1BWorkerPhaseReceipt, ...]
    elapsed_ns: int
    peak_resident_memory_bytes: int
    peak_scratch_bytes: int
    candidate_retry_count: int
    worker_declared_state_reset_count: int | None
    terminal_outcome: str | None
    terminal_failure_code: str | None
    receipt_origin: str

    def to_document(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "candidate_retry_count": self.candidate_retry_count,
            "candidate_role": self.candidate_role,
            "controller_observed_elapsed_ns": self.elapsed_ns,
            "receipt_origin": self.receipt_origin,
            "terminal_outcome": self.terminal_outcome,
            "terminal_failure_code": self.terminal_failure_code,
            "controller_observed_peak_resident_memory_bytes": (self.peak_resident_memory_bytes),
            "controller_observed_peak_scratch_bytes": self.peak_scratch_bytes,
            "phases": [phase.to_document() for phase in self.phases],
            "worker_declared_state_reset_count": self.worker_declared_state_reset_count,
        }


@dataclass(frozen=True, slots=True)
class Day1BWorkerCellReceipt:
    input_binding: Day1BWorkerProtocolContract
    f1m_controller_context_sha256: str
    f1m_route_coverage_sha256: str
    f1m_charged_size_class_set_sha256: str
    candidate: Day1BWorkerCandidateReceipt
    controller_schedule_phase_audits: tuple[Day1BWorkerPhaseAudit, ...]
    worker_declared_phase_audits_match_controller_schedule_audits: bool
    runtime_state_continuity_verified: bool
    controller_expected_f1m_size_class_set_sha256: str
    controller_expected_f1m_size_class_count: int
    controller_expected_f1m_phase_size_class_counts: tuple[int, int, int]
    controller_expected_f1m_phase_query_counts: tuple[int, int, int]
    controller_expected_f1m_phase_random_route_counts: tuple[int, int, int]
    controller_expected_f1m_phase_dummy_route_counts: tuple[int, int, int]
    controller_f1m_cardinality_derivation_root_sha256: str
    controller_expected_serialized_equivalence_class_count: int
    worker_observed_f1m_size_class_count: int
    worker_observed_f1m_materialized_binding_count: int
    pre_dispatch_context_sha256: str
    controller_registered_scratch_bytes_checkpoint_maximum: int
    controller_observed_registered_scratch_peak_bytes: int
    anonymous_scratch_creation_isolation_verified: bool
    controller_f1m_window_batch_stream_sha256: str
    weighted_query_range_coverage_verified: bool
    production_execution_admissible: bool
    object_receipt_spool_sha256: str
    object_receipt_line_count: int
    object_receipt_byte_count: int

    def __post_init__(self) -> None:
        if type(self.input_binding) is not Day1BWorkerProtocolContract:
            raise Day1BWorkerProtocolError(
                "worker receipt input binding must be one exact typed contract"
            )
        for field in (
            "f1m_controller_context_sha256",
            "f1m_route_coverage_sha256",
            "f1m_charged_size_class_set_sha256",
        ):
            _sha256(getattr(self, field), field)
        binding = self.input_binding
        if (
            self.f1m_controller_context_sha256 != binding.f1m_controller_context_sha256
            or self.f1m_route_coverage_sha256 != binding.f1m_route_coverage_sha256
            or self.f1m_charged_size_class_set_sha256 != binding.f1m_charged_size_class_set_sha256
            or self.candidate.candidate_id != binding.candidate.candidate_id
            or self.candidate.candidate_role != binding.candidate.candidate_role
            or self.controller_expected_f1m_size_class_set_sha256
            != binding.expected_f1m_size_class_set_sha256
            or self.controller_expected_f1m_size_class_count
            != binding.expected_f1m_size_class_count
            or self.controller_f1m_cardinality_derivation_root_sha256
            != binding.expected_f1m_cardinality_derivation_root_sha256
            or self.controller_expected_serialized_equivalence_class_count
            != binding.expected_serialized_equivalence_class_count
            or self.controller_registered_scratch_bytes_checkpoint_maximum
            != binding.resource_limits.controller_registered_scratch_bytes_checkpoint_maximum
        ):
            raise Day1BWorkerProtocolError(
                "worker receipt retargets its exact input-binding contract"
            )
        if (
            _strict_nonnegative(
                self.worker_observed_f1m_materialized_binding_count,
                "worker_observed_f1m_materialized_binding_count",
            )
            != 0
        ):
            raise Day1BWorkerProtocolError(
                "weighted Day1B cannot report materialized per-query F1-M bindings"
            )
        if type(self.weighted_query_range_coverage_verified) is not bool:
            raise Day1BWorkerProtocolError("weighted query-range coverage must be an exact boolean")
        if self.production_execution_admissible and not (
            self.anonymous_scratch_creation_isolation_verified
            and self.weighted_query_range_coverage_verified
        ):
            raise Day1BWorkerProtocolError(
                "weighted production admission requires isolation and range verification"
            )

    @property
    def input_binding_document(self) -> dict[str, object]:
        return self.input_binding.input_binding_document()

    @property
    def input_binding_sha256(self) -> str:
        return self.input_binding.input_binding_sha256

    def to_document(self) -> dict[str, object]:
        document: dict[str, object] = {
            "schema_version": DAY1B_WORKER_RECEIPT_SCHEMA,
            "candidate": self.candidate.to_document(),
            "controller_schedule_phase_audits": [
                audit.to_document() for audit in self.controller_schedule_phase_audits
            ],
            "controller_expected_f1m_size_class_count": (
                self.controller_expected_f1m_size_class_count
            ),
            "controller_expected_f1m_size_class_set_sha256": (
                self.controller_expected_f1m_size_class_set_sha256
            ),
            "controller_expected_f1m_phase_size_class_counts": dict(
                zip(
                    _PHASE_NAMES,
                    self.controller_expected_f1m_phase_size_class_counts,
                    strict=True,
                )
            ),
            "controller_expected_f1m_phase_query_counts": dict(
                zip(
                    _PHASE_NAMES,
                    self.controller_expected_f1m_phase_query_counts,
                    strict=True,
                )
            ),
            "controller_expected_f1m_phase_dummy_route_counts": dict(
                zip(
                    _PHASE_NAMES,
                    self.controller_expected_f1m_phase_dummy_route_counts,
                    strict=True,
                )
            ),
            "controller_expected_f1m_phase_random_route_counts": dict(
                zip(
                    _PHASE_NAMES,
                    self.controller_expected_f1m_phase_random_route_counts,
                    strict=True,
                )
            ),
            "controller_f1m_cardinality_derivation_root_sha256": (
                self.controller_f1m_cardinality_derivation_root_sha256
            ),
            "controller_expected_serialized_equivalence_class_count": (
                self.controller_expected_serialized_equivalence_class_count
            ),
            "controller_registered_scratch_bytes_checkpoint_maximum": (
                self.controller_registered_scratch_bytes_checkpoint_maximum
            ),
            "controller_observed_registered_scratch_peak_bytes": (
                self.controller_observed_registered_scratch_peak_bytes
            ),
            "anonymous_scratch_creation_isolation_verified": (
                self.anonymous_scratch_creation_isolation_verified
            ),
            "f1m_charged_size_class_set_sha256": (self.f1m_charged_size_class_set_sha256),
            "f1m_controller_context_sha256": self.f1m_controller_context_sha256,
            "f1m_route_coverage_sha256": self.f1m_route_coverage_sha256,
            "input_binding_document": self.input_binding_document,
            "input_binding_sha256": self.input_binding_sha256,
            "object_receipt_byte_count": self.object_receipt_byte_count,
            "object_receipt_line_count": self.object_receipt_line_count,
            "object_receipt_spool_sha256": self.object_receipt_spool_sha256,
            "raw_protocol_object_bytes_retained": False,
            "controller_f1m_window_batch_stream_sha256": (
                self.controller_f1m_window_batch_stream_sha256
            ),
            "pre_dispatch_context_sha256": self.pre_dispatch_context_sha256,
            "production_execution_admissible": self.production_execution_admissible,
            "runtime_state_continuity_verified": self.runtime_state_continuity_verified,
            "worker_declared_phase_audits_match_controller_schedule_audits": (
                self.worker_declared_phase_audits_match_controller_schedule_audits
            ),
            "worker_observed_f1m_size_class_count": (self.worker_observed_f1m_size_class_count),
            "worker_observed_f1m_materialized_binding_count": (
                self.worker_observed_f1m_materialized_binding_count
            ),
            "weighted_query_range_coverage_verified": (self.weighted_query_range_coverage_verified),
        }
        document["worker_candidate_cell_receipt_sha256"] = hashlib.sha256(
            _canonical_json_bytes(document)
        ).hexdigest()
        return document


_ANONYMOUS_SCRATCH_MEMBER_NAMES = (
    "binding-index.sqlite3",
    "object-receipts.jsonl",
)
_ANONYMOUS_SQLITE_APPLICATION_ID = int.from_bytes(b"DYCS", "big")


@dataclass(frozen=True, slots=True)
class _AnonymousScratchBinding:
    pre_dispatch_context_sha256: str
    controller_registered_scratch_bytes_checkpoint_maximum: int
    members: tuple[tuple[str, BinaryIO, tuple[int, int]], ...]
    anonymous_scratch_creation_isolation_verified: bool
    sqlite_connection: sqlite3.Connection | None = None


class Day1BAnonymousScratchCapability:
    """Opaque single-use already-open scratch handles minted by a launcher."""

    __slots__ = ("_binding", "__weakref__")

    def __new__(cls) -> Day1BAnonymousScratchCapability:
        raise TypeError("Day1B anonymous scratch capabilities are launcher-minted")

    def __bool__(self) -> bool:
        raise TypeError("Day1B anonymous scratch capability is not a caller boolean")


def _close_anonymous_scratch_binding(binding: _AnonymousScratchBinding) -> None:
    if binding.sqlite_connection is not None:
        with suppress(BaseException):
            binding.sqlite_connection.close()
    for _name, file, _identity in binding.members:
        with suppress(BaseException):
            file.close()


def _collected_anonymous_scratch(identifier: int) -> None:
    with _ANONYMOUS_SCRATCH_LOCK:
        active = _ISSUED_ANONYMOUS_SCRATCH.pop(identifier, None)
    if active is not None:
        binding = active[1]
        assert type(binding) is _AnonymousScratchBinding
        _close_anonymous_scratch_binding(binding)


def _mint_anonymous_scratch_capability(
    binding: _AnonymousScratchBinding,
) -> Day1BAnonymousScratchCapability:
    capability = object.__new__(Day1BAnonymousScratchCapability)
    object.__setattr__(capability, "_binding", binding)
    identifier = id(capability)
    reference = weakref.ref(
        capability,
        lambda _reference, identifier=identifier: _collected_anonymous_scratch(identifier),
    )
    with _ANONYMOUS_SCRATCH_LOCK:
        _ISSUED_ANONYMOUS_SCRATCH[identifier] = (reference, binding)
    return capability


def _claim_anonymous_scratch_capability(
    capability: Day1BAnonymousScratchCapability,
) -> _AnonymousScratchBinding:
    if type(capability) is not Day1BAnonymousScratchCapability:
        raise TypeError("anonymous scratch must be one exact launcher-minted capability")
    with _ANONYMOUS_SCRATCH_LOCK:
        active = _ISSUED_ANONYMOUS_SCRATCH.pop(id(capability), None)
    binding = _require_popped_authoritative_binding(
        active,
        capability=capability,
        presented=getattr(capability, "_binding", None),
        binding_type=_AnonymousScratchBinding,
        cleanup=lambda value: _close_anonymous_scratch_binding(value),
        error_message="anonymous scratch capability is absent, unissued, or consumed",
    )
    assert type(binding) is _AnonymousScratchBinding
    return binding


class _ControlledScratch:
    """Claimed launcher handles; this class performs no pathname mutation."""

    def __init__(
        self,
        capability: Day1BAnonymousScratchCapability,
        *,
        contract: Day1BWorkerProtocolContract,
        controller_phase_audits: tuple[Day1BWorkerPhaseAudit, ...],
    ) -> None:
        binding = _claim_anonymous_scratch_capability(capability)
        try:
            if type(contract) is not Day1BWorkerProtocolContract:
                raise TypeError("contract must be an exact Day1BWorkerProtocolContract")
            _validate_controller_phase_audits(contract, controller_phase_audits)
            expected_context = _pre_dispatch_context_sha256(
                contract,
                controller_phase_audits,
            )
            expected_limit = (
                contract.resource_limits.controller_registered_scratch_bytes_checkpoint_maximum
            )
            if (
                binding.pre_dispatch_context_sha256 != expected_context
                or binding.controller_registered_scratch_bytes_checkpoint_maximum != expected_limit
            ):
                raise Day1BWorkerProtocolError(
                    "anonymous scratch capability differs from pre-dispatch context or cap"
                )
            if binding.anonymous_scratch_creation_isolation_verified:
                raise Day1BWorkerProtocolError(
                    "test-only anonymous scratch cannot verify creation isolation"
                )
            if tuple(item[0] for item in binding.members) != _ANONYMOUS_SCRATCH_MEMBER_NAMES:
                raise Day1BWorkerProtocolError(
                    "anonymous scratch capability member roles are not exact"
                )
            if binding.sqlite_connection is None:
                raise Day1BWorkerProtocolError(
                    "anonymous scratch capability lacks its launcher-opened SQLite connection"
                )
            identities: set[tuple[int, int]] = set()
            files: dict[str, BinaryIO] = {}
            expected_identities: dict[str, tuple[int, int]] = {}
            for name, file, identity in binding.members:
                observed = os.fstat(file.fileno())
                observed_identity = observed.st_dev, observed.st_ino
                if (
                    not stat.S_ISREG(observed.st_mode)
                    or observed.st_nlink != 0
                    or observed.st_size != 0
                    or observed_identity != identity
                    or observed_identity in identities
                ):
                    raise Day1BWorkerProtocolError(
                        "anonymous scratch capability file identity is not exact "
                        "unlinked empty storage"
                    )
                identities.add(observed_identity)
                files[name] = file
                expected_identities[name] = identity
        except BaseException:
            _close_anonymous_scratch_binding(binding)
            raise
        self._byte_limit = expected_limit
        self._files = files
        self._identities = expected_identities
        self._sqlite_connection = binding.sqlite_connection
        self._claimed_names: set[str] = set()
        self.anonymous_scratch_creation_isolation_verified = (
            binding.anonymous_scratch_creation_isolation_verified
        )
        self._peak_bytes = 0
        self._closed = False
        self._lock = threading.Lock()

    def _claim_file(self, name: str) -> BinaryIO:
        if type(name) is not str or name not in _ANONYMOUS_SCRATCH_MEMBER_NAMES:
            raise Day1BWorkerProtocolError("controlled scratch member role is invalid")
        with self._lock:
            if self._closed:
                raise Day1BWorkerProtocolError("controlled invocation scratch is closed")
            if name in self._claimed_names:
                raise Day1BWorkerProtocolError("controlled scratch member role is already claimed")
            file = self._files[name]
            observed = os.fstat(file.fileno())
            if (
                not stat.S_ISREG(observed.st_mode)
                or observed.st_nlink != 0
                or (observed.st_dev, observed.st_ino) != self._identities[name]
            ):
                raise Day1BWorkerProtocolError("controlled anonymous scratch file identity changed")
            self._claimed_names.add(name)
            return file

    def create_binary_file(self, name: str) -> BinaryIO:
        if type(name) is not str or name != "object-receipts.jsonl":
            raise Day1BWorkerProtocolError("binary scratch member role is not exact")
        held = self._claim_file(name)
        descriptor: int | None = None
        try:
            descriptor = os.dup(held.fileno())
            duplicated = os.fstat(descriptor)
            if (
                not stat.S_ISREG(duplicated.st_mode)
                or duplicated.st_nlink != 0
                or (duplicated.st_dev, duplicated.st_ino) != self._identities[name]
            ):
                raise Day1BWorkerProtocolError(
                    "duplicated controlled scratch descriptor identity changed"
                )
            file = os.fdopen(descriptor, "w+b")
            descriptor = None
        except BaseException as error:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)
            held.close()
            if isinstance(error, Day1BWorkerProtocolError):
                raise
            raise Day1BWorkerProtocolError(
                "anonymous controlled scratch member handle could not be duplicated"
            ) from error
        return file

    def create_sqlite_connection(self, name: str) -> sqlite3.Connection:
        if type(name) is not str or name != "binding-index.sqlite3":
            raise Day1BWorkerProtocolError("SQLite scratch member role is not exact")
        held = self._claim_file(name)
        connection = self._sqlite_connection
        self._sqlite_connection = None
        try:
            if connection is None:
                raise Day1BWorkerProtocolError(
                    "launcher-opened anonymous SQLite connection is unavailable"
                )
            # SQLite may normalize an unlinked database to a platform-specific
            # filename.  The application-id round trip below proves the already-open
            # connection still writes the exact inode held by the capability.
            database_list = connection.execute("PRAGMA database_list").fetchall()
            database_row = database_list[0] if len(database_list) == 1 else None
            if (
                type(database_row) is not tuple
                or len(database_row) != 3
                or database_row[:2] != (0, "main")
                or type(database_row[2]) is not str
                or not database_row[2]
            ):
                raise Day1BWorkerProtocolError(
                    "anonymous SQLite connection is not bound to its held descriptor"
                )
            journal_mode = connection.execute("PRAGMA journal_mode=OFF").fetchone()
            locking_mode = connection.execute("PRAGMA locking_mode=EXCLUSIVE").fetchone()
            connection.execute("PRAGMA synchronous=OFF")
            connection.execute("PRAGMA temp_store=MEMORY")
            temp_store = connection.execute("PRAGMA temp_store").fetchone()
            if journal_mode != ("off",) or locking_mode != ("exclusive",) or temp_store != (2,):
                raise Day1BWorkerProtocolError(
                    "anonymous SQLite scratch did not enter its frozen no-sidecar mode"
                )
            connection.execute(f"PRAGMA application_id={_ANONYMOUS_SQLITE_APPLICATION_ID}")
            connection.commit()
            application_id = connection.execute("PRAGMA application_id").fetchone()
            held_application_id = int.from_bytes(os.pread(held.fileno(), 4, 68), "big")
            if application_id != (_ANONYMOUS_SQLITE_APPLICATION_ID,) or (
                held_application_id != _ANONYMOUS_SQLITE_APPLICATION_ID
            ):
                raise Day1BWorkerProtocolError(
                    "anonymous SQLite connection is not bound to its held file bytes"
                )
            self.require_within_cap()
        except BaseException as error:
            if connection is not None:
                with suppress(BaseException):
                    connection.close()
            held.close()
            if isinstance(error, Day1BWorkerProtocolError):
                raise
            raise Day1BWorkerProtocolError("anonymous SQLite scratch is unavailable") from error
        return connection

    def require_within_cap(self) -> None:
        if self._closed:
            raise Day1BWorkerProtocolError("controlled invocation scratch is closed")
        total = 0
        for name, file in self._files.items():
            if file.closed:
                raise Day1BWorkerProtocolError(
                    "controlled anonymous scratch file was closed outside its owner"
                )
            observed = os.fstat(file.fileno())
            if (
                not stat.S_ISREG(observed.st_mode)
                or observed.st_nlink != 0
                or (observed.st_dev, observed.st_ino) != self._identities[name]
            ):
                raise Day1BWorkerProtocolError("controlled anonymous scratch file identity changed")
            total += observed.st_size
        self._peak_bytes = max(self._peak_bytes, total)
        if total > self._byte_limit:
            raise Day1BWorkerProtocolError("controlled scratch exceeds its explicit cap")

    @property
    def peak_bytes(self) -> int:
        """Largest checkpointed sum of the two controller-owned member sizes."""

        return self._peak_bytes

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            file_error: BaseException | None = None
            if self._sqlite_connection is not None:
                try:
                    self._sqlite_connection.close()
                except BaseException as error:  # pragma: no cover - defensive cleanup
                    file_error = error
                self._sqlite_connection = None
            for file in self._files.values():
                try:
                    file.close()
                except BaseException as error:  # pragma: no cover - defensive cleanup
                    if file_error is None:
                        file_error = error
            if file_error is not None:
                raise Day1BWorkerProtocolError(
                    "anonymous controlled scratch descriptors could not be closed"
                ) from file_error


@dataclass(frozen=True, slots=True)
class Day1BExpectedF1MRegistryDescriptor:
    """Descriptive facts bound to an opaque controller size-class registry."""

    size_class_set_sha256: str
    size_class_count: int
    phase_size_class_counts: tuple[int, int, int]
    phase_query_counts: tuple[int, int, int]
    phase_random_route_counts: tuple[int, int, int]
    phase_dummy_route_counts: tuple[int, int, int]
    cardinality_derivation_root_sha256: str
    pre_dispatch_context_sha256: str
    controller_registered_scratch_bytes_checkpoint_maximum: int
    anonymous_scratch_creation_isolation_verified: bool
    controller_f1m_window_batch_stream_sha256: str
    weighted_query_range_coverage_verified: bool
    pre_dispatch_execution_admissible: bool

    def __post_init__(self) -> None:
        _sha256(self.size_class_set_sha256, "registry size_class_set_sha256")
        _strict_nonnegative(self.size_class_count, "registry size_class_count")
        for field in (
            "phase_size_class_counts",
            "phase_query_counts",
            "phase_random_route_counts",
            "phase_dummy_route_counts",
        ):
            value = getattr(self, field)
            if type(value) is not tuple or len(value) != len(_PHASE_NAMES):
                raise Day1BWorkerProtocolError(f"registry {field} is not an exact phase tuple")
            for count in value:
                _strict_nonnegative(count, f"registry {field}")
        if sum(self.phase_size_class_counts) != self.size_class_count:
            raise Day1BWorkerProtocolError("registry phase size-class counts do not sum exactly")
        for field in (
            "cardinality_derivation_root_sha256",
            "pre_dispatch_context_sha256",
            "controller_f1m_window_batch_stream_sha256",
        ):
            _sha256(getattr(self, field), f"registry {field}")
        _strict_positive(
            self.controller_registered_scratch_bytes_checkpoint_maximum,
            "registry controller_registered_scratch_bytes_checkpoint_maximum",
        )
        for field in (
            "anonymous_scratch_creation_isolation_verified",
            "weighted_query_range_coverage_verified",
            "pre_dispatch_execution_admissible",
        ):
            if type(getattr(self, field)) is not bool:
                raise Day1BWorkerProtocolError(f"registry {field} must be an exact boolean")
        if self.pre_dispatch_execution_admissible and not (
            self.anonymous_scratch_creation_isolation_verified
            and self.weighted_query_range_coverage_verified
        ):
            raise Day1BWorkerProtocolError(
                "registry production admission requires isolation and range verification"
            )

    def to_document(self) -> dict[str, object]:
        return {
            "schema_version": DAY1B_WORKER_EXPECTED_F1M_REGISTRY_DESCRIPTOR_SCHEMA,
            "anonymous_scratch_creation_isolation_verified": (
                self.anonymous_scratch_creation_isolation_verified
            ),
            "size_class_count": self.size_class_count,
            "size_class_set_sha256": self.size_class_set_sha256,
            "cardinality_derivation_root_sha256": self.cardinality_derivation_root_sha256,
            "controller_registered_scratch_bytes_checkpoint_maximum": (
                self.controller_registered_scratch_bytes_checkpoint_maximum
            ),
            "phase_size_class_counts": dict(
                zip(_PHASE_NAMES, self.phase_size_class_counts, strict=True)
            ),
            "phase_query_counts": dict(zip(_PHASE_NAMES, self.phase_query_counts, strict=True)),
            "phase_dummy_route_counts": dict(
                zip(_PHASE_NAMES, self.phase_dummy_route_counts, strict=True)
            ),
            "phase_random_route_counts": dict(
                zip(_PHASE_NAMES, self.phase_random_route_counts, strict=True)
            ),
            "controller_f1m_window_batch_stream_sha256": (
                self.controller_f1m_window_batch_stream_sha256
            ),
            "pre_dispatch_context_sha256": self.pre_dispatch_context_sha256,
            "pre_dispatch_execution_admissible": self.pre_dispatch_execution_admissible,
            "weighted_query_range_coverage_verified": (self.weighted_query_range_coverage_verified),
        }

    @classmethod
    def from_document(cls, value: object) -> Day1BExpectedF1MRegistryDescriptor:
        keys = {
            "schema_version",
            "anonymous_scratch_creation_isolation_verified",
            "size_class_count",
            "size_class_set_sha256",
            "cardinality_derivation_root_sha256",
            "controller_registered_scratch_bytes_checkpoint_maximum",
            "phase_size_class_counts",
            "phase_dummy_route_counts",
            "phase_query_counts",
            "phase_random_route_counts",
            "controller_f1m_window_batch_stream_sha256",
            "pre_dispatch_context_sha256",
            "pre_dispatch_execution_admissible",
            "weighted_query_range_coverage_verified",
        }
        if type(value) is not dict or set(value) != keys:
            raise Day1BWorkerProtocolError("expected F1-M registry descriptor keys are not exact")
        if value["schema_version"] != DAY1B_WORKER_EXPECTED_F1M_REGISTRY_DESCRIPTOR_SCHEMA:
            raise Day1BWorkerProtocolError("expected F1-M registry descriptor schema is not frozen")
        counts: dict[str, tuple[int, int, int]] = {}
        for field in (
            "phase_size_class_counts",
            "phase_dummy_route_counts",
            "phase_query_counts",
            "phase_random_route_counts",
        ):
            raw = value[field]
            if type(raw) is not dict or set(raw) != set(_PHASE_NAMES):
                raise Day1BWorkerProtocolError(
                    "expected F1-M registry descriptor phase keys are not exact"
                )
            counts[field] = tuple(raw[phase] for phase in _PHASE_NAMES)  # type: ignore[assignment]
        try:
            return cls(
                anonymous_scratch_creation_isolation_verified=(
                    value["anonymous_scratch_creation_isolation_verified"]
                ),
                size_class_count=value["size_class_count"],
                size_class_set_sha256=value["size_class_set_sha256"],
                cardinality_derivation_root_sha256=(value["cardinality_derivation_root_sha256"]),
                controller_registered_scratch_bytes_checkpoint_maximum=(
                    value["controller_registered_scratch_bytes_checkpoint_maximum"]
                ),
                phase_size_class_counts=counts["phase_size_class_counts"],
                phase_dummy_route_counts=counts["phase_dummy_route_counts"],
                phase_query_counts=counts["phase_query_counts"],
                phase_random_route_counts=counts["phase_random_route_counts"],
                controller_f1m_window_batch_stream_sha256=(
                    value["controller_f1m_window_batch_stream_sha256"]
                ),
                pre_dispatch_context_sha256=value["pre_dispatch_context_sha256"],
                pre_dispatch_execution_admissible=value["pre_dispatch_execution_admissible"],
                weighted_query_range_coverage_verified=(
                    value["weighted_query_range_coverage_verified"]
                ),
            )
        except (KeyError, TypeError) as error:  # pragma: no cover - exact keys above
            raise Day1BWorkerProtocolError(
                "expected F1-M registry descriptor is malformed"
            ) from error


def _create_expected_f1m_tables(connection: sqlite3.Connection) -> None:
    connection.execute(
        "CREATE TABLE expected_f1m ("
        "phase TEXT NOT NULL, window_index INTEGER NOT NULL, "
        "first_global_query_ordinal INTEGER NOT NULL, category TEXT NOT NULL, "
        "category_order INTEGER NOT NULL CHECK(category_order IN (0,1)), "
        "object_ordinal INTEGER NOT NULL, size_class_sha256 TEXT NOT NULL, "
        "multiplicity INTEGER NOT NULL "
        "CHECK(multiplicity > 0), route_document BLOB NOT NULL, "
        "observed INTEGER NOT NULL CHECK(observed IN (0,1)), "
        "PRIMARY KEY(phase, category, object_ordinal)) WITHOUT ROWID"
    )
    connection.execute(
        "CREATE TABLE f1m_window_cardinality ("
        "phase TEXT NOT NULL, window_index INTEGER NOT NULL, "
        "accepted_group_start INTEGER NOT NULL, accepted_group_end INTEGER NOT NULL, "
        "first_global_query_ordinal INTEGER NOT NULL, query_count INTEGER NOT NULL, "
        "version_id TEXT NOT NULL, output_plan_digest TEXT NOT NULL, "
        "private_plan_digest TEXT NOT NULL, execution_binding_digest TEXT NOT NULL, "
        "f1m_policy TEXT NOT NULL, "
        "expected_random_route_count INTEGER NOT NULL, "
        "expected_dummy_route_count INTEGER NOT NULL, "
        "expected_size_class_subroot_sha256 TEXT NOT NULL, "
        "PRIMARY KEY(phase, window_index)) WITHOUT ROWID"
    )
    connection.execute(
        "CREATE TABLE f1m_window_batches ("
        "phase TEXT NOT NULL, window_index INTEGER NOT NULL, "
        "first_global_query_ordinal INTEGER NOT NULL, "
        "query_count INTEGER NOT NULL CHECK(query_count > 0), "
        "version_id TEXT NOT NULL, "
        "output_plan_digest TEXT NOT NULL, private_plan_digest TEXT NOT NULL, "
        "execution_binding_digest TEXT NOT NULL, size_class_subroot_sha256 TEXT NOT NULL, "
        "PRIMARY KEY(phase, window_index)) WITHOUT ROWID"
    )
    connection.execute(
        "CREATE INDEX expected_f1m_by_window_order ON expected_f1m("
        "phase, window_index, object_ordinal, category_order)"
    )
    connection.execute(
        "CREATE INDEX expected_f1m_by_window_category ON expected_f1m("
        "phase, window_index, category)"
    )
    connection.execute(
        "CREATE INDEX expected_f1m_by_batch_order ON expected_f1m("
        "phase, window_index, first_global_query_ordinal, multiplicity, "
        "object_ordinal, category_order)"
    )
    connection.execute(
        "CREATE INDEX f1m_window_batches_by_window ON f1m_window_batches(phase, window_index)"
    )


def _insert_f1m_window_cardinality(
    connection: sqlite3.Connection,
    row: Day1BF1MWindowCardinality,
) -> None:
    try:
        connection.execute(
            "INSERT INTO f1m_window_cardinality VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                row.phase,
                row.window_index,
                row.accepted_group_start,
                row.accepted_group_end,
                row.first_global_query_ordinal,
                row.query_count,
                row.version_id,
                row.output_plan_digest,
                row.private_plan_digest,
                row.execution_binding_digest,
                row.f1m_policy,
                row.expected_random_route_count,
                row.expected_dummy_route_count,
                row.expected_size_class_subroot_sha256,
            ),
        )
    except sqlite3.IntegrityError as error:
        raise Day1BWorkerProtocolError(
            "F1-M window cardinality rows repeat a phase/window identity"
        ) from error


def _insert_f1m_window_batch(
    connection: sqlite3.Connection,
    row: Day1BF1MWindowBatch,
) -> None:
    window = connection.execute(
        "SELECT first_global_query_ordinal, query_count, version_id, "
        "output_plan_digest, private_plan_digest, execution_binding_digest "
        "FROM f1m_window_cardinality WHERE phase=? AND window_index=?",
        (row.phase, row.window_index),
    ).fetchone()
    if window is None:
        raise Day1BWorkerProtocolError(
            "F1-M window batch is absent from controller window cardinality"
        )
    first_query, query_count, version_id, output_plan, private_plan, execution = window
    if (row.first_global_query_ordinal, row.query_count) != (first_query, query_count):
        raise Day1BWorkerProtocolError(
            "F1-M window batch query range is not its exact controller window"
        )
    if (
        row.version_id,
        row.output_plan_digest,
        row.private_plan_digest,
        row.execution_binding_digest,
    ) != (version_id, output_plan, private_plan, execution):
        raise Day1BWorkerProtocolError(
            "F1-M window batch differs from its OutputPlan/cardinality identity"
        )
    try:
        connection.execute(
            "INSERT INTO f1m_window_batches VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                row.phase,
                row.window_index,
                row.first_global_query_ordinal,
                row.query_count,
                row.version_id,
                row.output_plan_digest,
                row.private_plan_digest,
                row.execution_binding_digest,
                row.size_class_subroot_sha256,
            ),
        )
    except sqlite3.IntegrityError as error:
        raise Day1BWorkerProtocolError(
            "F1-M window batches repeat one phase/window identity"
        ) from error


def _insert_expected_f1m(
    connection: sqlite3.Connection,
    item: Day1BControllerExpectedF1MObject,
) -> None:
    try:
        connection.execute(
            "INSERT INTO expected_f1m VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
            (
                item.phase,
                item.window_index,
                item.first_global_query_ordinal,
                item.category,
                DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES.index(item.category),
                item.object_ordinal,
                hashlib.sha256(
                    _canonical_json_bytes(item.f1m_size_class.to_document())
                ).hexdigest(),
                item.multiplicity,
                _canonical_json_bytes(item.to_document()),
            ),
        )
    except sqlite3.IntegrityError as error:
        raise Day1BWorkerProtocolError(
            "controller expected F1-M size classes repeat one canonical route identity"
        ) from error
    size_class = item.f1m_size_class
    admitted_batch = connection.execute(
        "SELECT phase, window_index, first_global_query_ordinal, query_count, version_id, "
        "output_plan_digest, private_plan_digest, execution_binding_digest "
        "FROM f1m_window_batches WHERE phase=? AND window_index=? "
        "AND first_global_query_ordinal=? AND query_count=?",
        (
            item.phase,
            item.window_index,
            item.first_global_query_ordinal,
            item.multiplicity,
        ),
    ).fetchone()
    if admitted_batch != (
        item.phase,
        item.window_index,
        item.first_global_query_ordinal,
        item.multiplicity,
        size_class.version_id,
        size_class.output_plan_digest,
        size_class.private_plan_digest,
        size_class.execution_binding_digest,
    ):
        raise Day1BWorkerProtocolError(
            "controller expected F1-M query range fields are not shared across its size classes"
        )
    window = connection.execute(
        "SELECT first_global_query_ordinal, query_count, version_id, "
        "output_plan_digest, private_plan_digest, execution_binding_digest "
        "FROM f1m_window_cardinality WHERE phase=? AND window_index=?",
        (item.phase, item.window_index),
    ).fetchone()
    if window is None:
        raise Day1BWorkerProtocolError(
            "expected F1-M size class is absent from controller window cardinality"
        )
    first_query, query_count, version_id, output_plan, private_plan, execution = window
    if not (
        first_query <= item.first_global_query_ordinal
        and item.first_global_query_ordinal + item.multiplicity <= first_query + query_count
    ):
        raise Day1BWorkerProtocolError(
            "expected F1-M size-class query range is outside its controller window"
        )
    if (
        size_class.version_id,
        size_class.output_plan_digest,
        size_class.private_plan_digest,
        size_class.execution_binding_digest,
    ) != (version_id, output_plan, private_plan, execution):
        raise Day1BWorkerProtocolError(
            "expected F1-M size class differs from its OutputPlan/cardinality identity"
        )


class _ExpectedF1MRegistry:
    """Descriptor-backed expected-size-class registry built from one bounded stream."""

    def __init__(
        self,
        scratch: _ControlledScratch,
        *,
        contract: Day1BWorkerProtocolContract,
        controller_phase_audits: tuple[Day1BWorkerPhaseAudit, ...],
        window_cardinalities: Iterable[Day1BF1MWindowCardinality],
        window_batches: Iterable[Day1BF1MWindowBatch],
        expected_f1m_objects: Iterable[Day1BControllerExpectedF1MObject],
    ) -> None:
        self.scratch = scratch
        self._closed = False
        self._transferred = False
        self._close_lock = threading.Lock()
        sqlite_name = "binding-index.sqlite3"
        try:
            if type(contract) is not Day1BWorkerProtocolContract:
                raise TypeError("contract must be an exact Day1BWorkerProtocolContract")
            _validate_controller_phase_audits(contract, controller_phase_audits)
            self.connection = scratch.create_sqlite_connection(sqlite_name)
            # The database is opened from one held anonymous descriptor. SQLite
            # sort/temporary state stays in memory and is not described by the
            # checkpointed on-disk scratch-byte contract.
            _create_expected_f1m_tables(self.connection)
            self.connection.commit()
            scratch.require_within_cap()
            window_root = self._ingest_windows(window_cardinalities)
            window_batch_root = self._ingest_batches(window_batches)
            self.descriptor = self._ingest_routes(
                expected_f1m_objects,
                window_root=window_root,
                window_batch_root=window_batch_root,
                pre_dispatch_context_sha256=_pre_dispatch_context_sha256(
                    contract,
                    controller_phase_audits,
                ),
                controller_registered_scratch_bytes_checkpoint_maximum=(
                    contract.resource_limits.controller_registered_scratch_bytes_checkpoint_maximum
                ),
                anonymous_scratch_creation_isolation_verified=(
                    scratch.anonymous_scratch_creation_isolation_verified
                ),
            )
        except BaseException:
            self._closed = True
            connection = getattr(self, "connection", None)
            if connection is not None:
                with suppress(BaseException):
                    connection.close()
            scratch.close()
            raise

    def _iter_exact(
        self,
        value: Iterable[object],
        *,
        field: str,
    ) -> Iterable[object]:
        try:
            return iter(value)
        except TypeError as error:
            raise TypeError(f"{field} must be a one-pass iterable") from error

    def _checkpoint(self, count: int) -> None:
        if count % _EXPECTED_REGISTRY_INGEST_BATCH_SIZE == 0:
            self.connection.commit()
            self.scratch.require_within_cap()

    def _ingest_windows(
        self,
        rows: Iterable[Day1BF1MWindowCardinality],
    ) -> str:
        phase_order = {phase: index for index, phase in enumerate(_PHASE_NAMES)}
        previous: tuple[int, int] | None = None
        hasher = hashlib.sha256()
        hasher.update(b'{"windows":[')
        count = 0
        for count, raw_row in enumerate(
            self._iter_exact(rows, field="F1-M window cardinalities"),
            start=1,
        ):
            if type(raw_row) is not Day1BF1MWindowCardinality:
                raise Day1BWorkerProtocolError(
                    "F1-M window cardinality stream contains a non-exact row"
                )
            row = raw_row
            order = phase_order[row.phase], row.window_index
            if previous is not None and order <= previous:
                raise Day1BWorkerProtocolError(
                    "F1-M window cardinalities are not unique canonical order"
                )
            previous = order
            if count > 1:
                hasher.update(b",")
            hasher.update(_canonical_json_bytes(row.to_document())[:-1])
            _insert_f1m_window_cardinality(self.connection, row)
            self._checkpoint(count)
        hasher.update(b'],"schema_version":"dynamic-cssc-day1b-f1m-window-cardinality-set-v3"}\n')
        self.connection.commit()
        self.scratch.require_within_cap()
        return hasher.hexdigest()

    def _ingest_batches(
        self,
        rows: Iterable[Day1BF1MWindowBatch],
    ) -> str:
        phase_order = {phase: index for index, phase in enumerate(_PHASE_NAMES)}
        previous: tuple[int, int] | None = None
        hasher = hashlib.sha256()
        hasher.update(b'{"window_batches":[')
        count = 0
        for count, raw_row in enumerate(
            self._iter_exact(rows, field="F1-M window batches"),
            start=1,
        ):
            if type(raw_row) is not Day1BF1MWindowBatch:
                raise Day1BWorkerProtocolError("F1-M window-batch stream contains a non-exact row")
            row = raw_row
            order = phase_order[row.phase], row.window_index
            if previous is not None and order <= previous:
                raise Day1BWorkerProtocolError("F1-M window batches are not unique canonical order")
            previous = order
            if count > 1:
                hasher.update(b",")
            hasher.update(_canonical_json_bytes(row.to_document())[:-1])
            _insert_f1m_window_batch(self.connection, row)
            self._checkpoint(count)
        hasher.update(b'],"schema_version":"dynamic-cssc-day1b-f1m-window-batch-set-v1"}\n')
        self.connection.commit()
        self.scratch.require_within_cap()
        return hasher.hexdigest()

    @staticmethod
    def _size_class_subroot(size_class_documents: Iterable[bytes]) -> str:
        hasher = hashlib.sha256()
        hasher.update(b'{"routes":[')
        count = 0
        for count, raw in enumerate(size_class_documents, start=1):
            if type(raw) is not bytes or not raw.endswith(b"\n"):
                raise Day1BWorkerProtocolError(
                    "expected F1-M size-class document spool is malformed"
                )
            if count > 1:
                hasher.update(b",")
            hasher.update(raw[:-1])
        hasher.update(
            b'],"schema_version":'
            + json.dumps(_DAY1B_WORKER_EXPECTED_F1M_SIZE_CLASS_SUBROOT_SCHEMA).encode("ascii")
            + b"}\n"
        )
        return hasher.hexdigest()

    def _validate_route_cardinality(self) -> None:
        for row in self.connection.execute(
            "SELECT phase, window_index, expected_random_route_count, "
            "expected_dummy_route_count, expected_size_class_subroot_sha256, "
            "first_global_query_ordinal, query_count "
            "FROM f1m_window_cardinality ORDER BY phase, window_index"
        ):
            (
                phase,
                window_index,
                expected_random,
                expected_dummy,
                expected_subroot,
                first_query,
                query_count,
            ) = row
            window_batch = self.connection.execute(
                "SELECT first_global_query_ordinal, query_count, "
                "size_class_subroot_sha256 FROM f1m_window_batches "
                "WHERE phase=? AND window_index=?",
                (phase, window_index),
            ).fetchone()
            if (query_count == 0 and window_batch is not None) or (
                query_count > 0 and window_batch != (first_query, query_count, expected_subroot)
            ):
                raise Day1BWorkerProtocolError(
                    "F1-M window batch does not exactly cover its query-bearing window"
                )
            observed = dict(
                self.connection.execute(
                    "SELECT category, SUM(multiplicity) FROM expected_f1m "
                    "WHERE phase=? AND window_index=? GROUP BY category",
                    (phase, window_index),
                )
            )
            if (
                observed.get(
                    DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES[0],
                    0,
                )
                != expected_random
                or observed.get(DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES[1], 0)
                != expected_dummy
            ):
                raise Day1BWorkerProtocolError(
                    "expected F1-M size classes differ from OutputPlan-derived cardinality"
                )
            documents = (
                result[0]
                for result in self.connection.execute(
                    "SELECT route_document FROM expected_f1m "
                    "WHERE phase=? AND window_index=? "
                    "ORDER BY object_ordinal, category_order",
                    (phase, window_index),
                )
            )
            if self._size_class_subroot(documents) != expected_subroot:
                raise Day1BWorkerProtocolError(
                    "expected F1-M window size-class subroot differs from exact descriptors"
                )

    def _ingest_routes(
        self,
        expected_f1m_objects: Iterable[Day1BControllerExpectedF1MObject],
        *,
        window_root: str,
        window_batch_root: str,
        pre_dispatch_context_sha256: str,
        controller_registered_scratch_bytes_checkpoint_maximum: int,
        anonymous_scratch_creation_isolation_verified: bool,
    ) -> Day1BExpectedF1MRegistryDescriptor:
        iterator = self._iter_exact(
            expected_f1m_objects,
            field="expected F1-M objects",
        )
        phase_order = {phase: index for index, phase in enumerate(_PHASE_NAMES)}
        category_order = {
            category: index
            for index, category in enumerate(DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES)
        }
        previous_order: tuple[int, int, int, int] | None = None
        hasher = hashlib.sha256()
        hasher.update(b'{"objects":[')
        phase_size_class_counts = [0, 0, 0]
        phase_random_counts = [0, 0, 0]
        phase_dummy_counts = [0, 0, 0]
        next_object_ordinals: dict[tuple[str, str], int] = {}
        count = 0
        for raw_item in iterator:
            if type(raw_item) is not Day1BControllerExpectedF1MObject:
                raise Day1BWorkerProtocolError(
                    "expected F1-M stream contains a non-exact descriptor"
                )
            item = raw_item
            order = _expected_f1m_order(item, phase_order, category_order)
            if previous_order is not None and order <= previous_order:
                raise Day1BWorkerProtocolError(
                    "expected F1-M stream is not unique canonical size-class order"
                )
            previous_order = order
            ordinal_key = item.phase, item.category
            expected_ordinal = next_object_ordinals.get(ordinal_key, 0)
            if item.object_ordinal != expected_ordinal:
                raise Day1BWorkerProtocolError(
                    "expected F1-M object ordinals must be contiguous from zero "
                    "within each phase/category"
                )
            next_object_ordinals[ordinal_key] = expected_ordinal + 1
            if count:
                hasher.update(b",")
            hasher.update(_canonical_json_bytes(item.to_document())[:-1])
            _insert_expected_f1m(self.connection, item)
            phase_index = phase_order[item.phase]
            phase_size_class_counts[phase_index] += 1
            if item.category == DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES[0]:
                phase_random_counts[phase_index] += item.multiplicity
            else:
                phase_dummy_counts[phase_index] += item.multiplicity
            count += 1
            self._checkpoint(count)
        hasher.update(
            b'],"schema_version":'
            + json.dumps(DAY1B_WORKER_EXPECTED_F1M_SIZE_CLASS_SET_SCHEMA).encode("ascii")
            + b"}\n"
        )
        self.connection.commit()
        self.scratch.require_within_cap()
        self._validate_route_cardinality()
        phase_query_counts = tuple(
            int(
                self.connection.execute(
                    "SELECT COALESCE(SUM(query_count),0) FROM f1m_window_batches WHERE phase=?",
                    (phase,),
                ).fetchone()[0]
            )
            for phase in _PHASE_NAMES
        )
        size_class_set_sha256 = hasher.hexdigest()
        cardinality_root = hashlib.sha256(
            _canonical_json_bytes(
                {
                    "size_class_set_sha256": size_class_set_sha256,
                    "window_batch_stream_sha256": window_batch_root,
                    "schema_version": "dynamic-cssc-day1b-f1m-cardinality-derivation-v4",
                    "window_cardinality_stream_sha256": window_root,
                }
            )
        ).hexdigest()
        return Day1BExpectedF1MRegistryDescriptor(
            size_class_set_sha256=size_class_set_sha256,
            size_class_count=count,
            phase_size_class_counts=tuple(phase_size_class_counts),  # type: ignore[arg-type]
            phase_query_counts=phase_query_counts,  # type: ignore[arg-type]
            phase_random_route_counts=tuple(phase_random_counts),  # type: ignore[arg-type]
            phase_dummy_route_counts=tuple(phase_dummy_counts),  # type: ignore[arg-type]
            cardinality_derivation_root_sha256=cardinality_root,
            pre_dispatch_context_sha256=pre_dispatch_context_sha256,
            controller_registered_scratch_bytes_checkpoint_maximum=(
                controller_registered_scratch_bytes_checkpoint_maximum
            ),
            anonymous_scratch_creation_isolation_verified=(
                anonymous_scratch_creation_isolation_verified
            ),
            controller_f1m_window_batch_stream_sha256=window_batch_root,
            weighted_query_range_coverage_verified=True,
            pre_dispatch_execution_admissible=False,
        )

    def validate_for_invocation(
        self,
        contract: Day1BWorkerProtocolContract,
        controller_phase_audits: tuple[Day1BWorkerPhaseAudit, ...],
    ) -> None:
        if (
            self.descriptor.cardinality_derivation_root_sha256
            != contract.expected_f1m_cardinality_derivation_root_sha256
        ):
            raise Day1BWorkerProtocolError(
                "F1-M cardinality derivation root differs from the worker input binding"
            )
        if self.descriptor.pre_dispatch_context_sha256 != _pre_dispatch_context_sha256(
            contract,
            controller_phase_audits,
        ):
            raise Day1BWorkerProtocolError(
                "expected F1-M registry pre-dispatch context differs from invocation"
            )
        for phase_index, phase in enumerate(_PHASE_NAMES):
            rows = tuple(
                self.connection.execute(
                    "SELECT accepted_group_start, accepted_group_end, query_count, f1m_policy "
                    "FROM f1m_window_cardinality WHERE phase=? ORDER BY window_index",
                    (phase,),
                )
            )
            retained = phase in contract.candidate.retained_phases
            if not retained and rows:
                raise Day1BWorkerProtocolError(
                    "F1-M cardinality cannot target a non-retained phase"
                )
            if retained:
                audit = controller_phase_audits[phase_index]
                if len(rows) != audit.realized_window_count:
                    raise Day1BWorkerProtocolError(
                        "F1-M cardinality rows do not cover every controller window"
                    )
                if sum(row[2] for row in rows) != audit.realized_query_count:
                    raise Day1BWorkerProtocolError(
                        "F1-M cardinality query totals differ from controller audit"
                    )
                phase_range = contract.phase_ranges[phase_index]
                if any(
                    row[0] < phase_range.accepted_group_start
                    or row[1] > phase_range.accepted_group_end
                    or row[3] != contract.candidate.f1m_policy
                    for row in rows
                ):
                    raise Day1BWorkerProtocolError(
                        "F1-M window range/policy differs from candidate and schedule"
                    )

    def transfer_to_spool(self) -> tuple[_ControlledScratch, sqlite3.Connection]:
        if self._closed or self._transferred:
            raise Day1BWorkerProtocolError("expected F1-M registry is unavailable")
        self._transferred = True
        return self.scratch, self.connection

    def close(self) -> None:
        with self._close_lock:
            if self._closed or self._transferred:
                return
            self._closed = True
            try:
                self.connection.close()
            finally:
                self.scratch.close()


@dataclass(frozen=True, slots=True)
class _ExpectedRegistryBinding:
    registry: _ExpectedF1MRegistry


class Day1BExpectedF1MRegistryCapability:
    """Opaque single-use expected size-class registry minted by a controller."""

    __slots__ = ("_binding", "__weakref__")

    def __new__(cls) -> Day1BExpectedF1MRegistryCapability:
        raise TypeError("Day1B expected F1-M registries are controller-minted")

    def __bool__(self) -> bool:
        raise TypeError("Day1B expected F1-M registry is not a caller boolean")


def _collected_expected_registry(identifier: int) -> None:
    with _EXPECTED_REGISTRY_LOCK:
        active = _ISSUED_EXPECTED_REGISTRIES.pop(identifier, None)
    if active is not None:
        binding = active[1]
        assert type(binding) is _ExpectedRegistryBinding
        binding.registry.close()


def _mint_expected_registry_capability(
    registry: _ExpectedF1MRegistry,
) -> Day1BExpectedF1MRegistryCapability:
    binding = _ExpectedRegistryBinding(registry=registry)
    capability = object.__new__(Day1BExpectedF1MRegistryCapability)
    object.__setattr__(capability, "_binding", binding)
    identifier = id(capability)
    reference = weakref.ref(
        capability,
        lambda _reference, identifier=identifier: _collected_expected_registry(identifier),
    )
    with _EXPECTED_REGISTRY_LOCK:
        _ISSUED_EXPECTED_REGISTRIES[identifier] = (reference, binding)
    return capability


def _active_expected_registry_binding(
    capability: Day1BExpectedF1MRegistryCapability,
    *,
    consume: bool,
) -> _ExpectedRegistryBinding:
    if type(capability) is not Day1BExpectedF1MRegistryCapability:
        raise TypeError("expected F1-M registry must be exact controller-minted evidence")
    with _EXPECTED_REGISTRY_LOCK:
        active = (
            _ISSUED_EXPECTED_REGISTRIES.pop(id(capability), None)
            if consume
            else _ISSUED_EXPECTED_REGISTRIES.get(id(capability))
        )
    presented = getattr(capability, "_binding", None)
    error_message = "expected F1-M registry capability is absent, unissued, or consumed"
    if consume:
        binding = _require_popped_authoritative_binding(
            active,
            capability=capability,
            presented=presented,
            binding_type=_ExpectedRegistryBinding,
            cleanup=lambda value: value.registry.close(),
            error_message=error_message,
        )
    else:
        if (
            active is None
            or active[0]() is not capability
            or active[1] is not presented
            or type(presented) is not _ExpectedRegistryBinding
        ):
            raise Day1BWorkerProtocolError(error_message)
        binding = presented
    assert type(binding) is _ExpectedRegistryBinding
    return binding


def describe_day1b_expected_f1m_registry(
    capability: Day1BExpectedF1MRegistryCapability,
) -> Day1BExpectedF1MRegistryDescriptor:
    """Read non-authoritative registry facts without consuming the capability."""

    return _active_expected_registry_binding(capability, consume=False).registry.descriptor


def abandon_day1b_expected_f1m_registry(
    capability: Day1BExpectedF1MRegistryCapability,
) -> None:
    """Consume an unused expected-size-class registry and clean its controlled scratch."""

    binding = _active_expected_registry_binding(capability, consume=True)
    binding.registry.close()


def _test_only_issue_day1b_anonymous_scratch_capability(
    *,
    contract: Day1BWorkerProtocolContract,
    controller_phase_audits: tuple[Day1BWorkerPhaseAudit, ...],
    controlled_scratch_root: Path,
    handles: tuple[BinaryIO, ...] | None = None,
) -> Day1BAnonymousScratchCapability:
    """Mint unverified already-open scratch handles for private fixtures only."""

    _require_test_invocation_issuer()
    if type(contract) is not Day1BWorkerProtocolContract:
        raise TypeError("contract must be an exact Day1BWorkerProtocolContract")
    _validate_controller_phase_audits(contract, controller_phase_audits)
    if not isinstance(controlled_scratch_root, Path):
        raise TypeError("controlled_scratch_root must be a Path")
    try:
        root_entries = tuple(controlled_scratch_root.iterdir())
    except OSError as error:
        raise Day1BWorkerProtocolError(
            "test-only scratch observation root is unavailable"
        ) from error
    if root_entries:
        raise Day1BWorkerProtocolError("test-only scratch observation root must be empty")
    owned: tuple[BinaryIO, ...]
    sqlite_connection: sqlite3.Connection | None = None
    if handles is None:
        created: list[BinaryIO] = []
        root_descriptor: int | None = None
        sqlite_file: BinaryIO | None = None
        sqlite_path: Path | None = None
        sqlite_link_name: str | None = None
        try:
            root_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
            root_descriptor = os.open(controlled_scratch_root, root_flags)
            held_root = os.fstat(root_descriptor)
            visible_root = os.stat(controlled_scratch_root, follow_symlinks=False)
            if (
                not stat.S_ISDIR(held_root.st_mode)
                or not stat.S_ISDIR(visible_root.st_mode)
                or (held_root.st_dev, held_root.st_ino)
                != (visible_root.st_dev, visible_root.st_ino)
            ):
                raise Day1BWorkerProtocolError(
                    "test-only scratch observation root identity is not exact"
                )

            # SQLite must first open a secure, launcher-visible name.  The launcher
            # verifies that name against both its directory and file descriptors,
            # unlinks it, and only then mints the capability.  This avoids Linux's
            # non-portable /dev/fd SQLite reopen semantics while leaving no name for
            # claimed worker code to resolve or mutate.
            sqlite_file = tempfile.NamedTemporaryFile(  # noqa: SIM115
                mode="w+b",
                dir=controlled_scratch_root,
                prefix=".day1b-sqlite-",
                delete=False,
            )
            created.append(sqlite_file)
            sqlite_path = Path(sqlite_file.name)
            sqlite_link_name = sqlite_path.name
            held_sqlite = os.fstat(sqlite_file.fileno())
            linked_sqlite = os.stat(
                sqlite_link_name,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
            sqlite_identity = held_sqlite.st_dev, held_sqlite.st_ino
            if (
                not stat.S_ISREG(held_sqlite.st_mode)
                or held_sqlite.st_nlink != 1
                or held_sqlite.st_size != 0
                or (linked_sqlite.st_dev, linked_sqlite.st_ino) != sqlite_identity
            ):
                raise Day1BWorkerProtocolError(
                    "launcher-visible SQLite scratch identity is not exact"
                )
            sqlite_connection = sqlite3.connect(
                f"{sqlite_path.as_uri()}?mode=rw",
                check_same_thread=False,
                uri=True,
            )
            held_after_connect = os.fstat(sqlite_file.fileno())
            linked_after_connect = os.stat(
                sqlite_link_name,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
            visible_after_connect = os.stat(sqlite_path, follow_symlinks=False)
            if (
                (held_after_connect.st_dev, held_after_connect.st_ino) != sqlite_identity
                or (linked_after_connect.st_dev, linked_after_connect.st_ino) != sqlite_identity
                or (visible_after_connect.st_dev, visible_after_connect.st_ino) != sqlite_identity
                or held_after_connect.st_nlink != 1
                or held_after_connect.st_size != 0
            ):
                raise Day1BWorkerProtocolError(
                    "launcher-visible SQLite scratch changed while it was opened"
                )
            os.unlink(sqlite_link_name, dir_fd=root_descriptor)
            unlinked_sqlite = os.fstat(sqlite_file.fileno())
            if (
                (unlinked_sqlite.st_dev, unlinked_sqlite.st_ino) != sqlite_identity
                or unlinked_sqlite.st_nlink != 0
                or unlinked_sqlite.st_size != 0
            ):
                raise Day1BWorkerProtocolError(
                    "launcher-opened SQLite scratch did not become exact anonymous storage"
                )
            sqlite_link_name = None

            # The fixture source is deliberately not a production/isolation fact.
            created.append(tempfile.TemporaryFile(mode="w+b"))  # noqa: SIM115
        except BaseException:
            if sqlite_connection is not None:
                with suppress(BaseException):
                    sqlite_connection.close()
            if sqlite_file is not None and sqlite_link_name is not None:
                expected_identity: tuple[int, int] | None = None
                with suppress(BaseException):
                    observed = os.fstat(sqlite_file.fileno())
                    expected_identity = observed.st_dev, observed.st_ino
                removed_from_held_root = False
                if root_descriptor is not None and expected_identity is not None:
                    try:
                        linked = os.stat(
                            sqlite_link_name,
                            dir_fd=root_descriptor,
                            follow_symlinks=False,
                        )
                        if (linked.st_dev, linked.st_ino) == expected_identity:
                            os.unlink(sqlite_link_name, dir_fd=root_descriptor)
                            removed_from_held_root = True
                    except OSError:
                        pass
                if (
                    not removed_from_held_root
                    and sqlite_path is not None
                    and expected_identity is not None
                ):
                    try:
                        linked = os.stat(sqlite_path, follow_symlinks=False)
                        if (linked.st_dev, linked.st_ino) == expected_identity:
                            os.unlink(sqlite_path)
                    except OSError:
                        pass
            for file in created:
                with suppress(BaseException):
                    file.close()
            raise
        finally:
            if root_descriptor is not None:
                with suppress(OSError):
                    os.close(root_descriptor)
        owned = tuple(created)
    elif type(handles) is tuple:
        owned = handles
    else:
        raise TypeError("test-only anonymous scratch handles must be an exact tuple")
    try:
        if len(owned) != len(_ANONYMOUS_SCRATCH_MEMBER_NAMES):
            raise Day1BWorkerProtocolError(
                "anonymous scratch capability requires exactly two member handles"
            )
        members: list[tuple[str, BinaryIO, tuple[int, int]]] = []
        identities: set[tuple[int, int]] = set()
        for name, file in zip(_ANONYMOUS_SCRATCH_MEMBER_NAMES, owned, strict=True):
            if not callable(getattr(file, "fileno", None)):
                raise Day1BWorkerProtocolError(
                    "anonymous scratch capability member is not an open file"
                )
            observed = os.fstat(file.fileno())
            identity = observed.st_dev, observed.st_ino
            if (
                not stat.S_ISREG(observed.st_mode)
                or observed.st_nlink != 0
                or observed.st_size != 0
                or identity in identities
            ):
                raise Day1BWorkerProtocolError(
                    "anonymous scratch capability requires distinct unlinked empty files"
                )
            identities.add(identity)
            members.append((name, file, identity))
    except BaseException:
        if sqlite_connection is not None:
            with suppress(BaseException):
                sqlite_connection.close()
        for file in owned:
            with suppress(BaseException):
                file.close()
        raise
    if sqlite_connection is None:
        for file in owned:
            with suppress(BaseException):
                file.close()
        raise Day1BWorkerProtocolError(
            "custom anonymous scratch handles lack a launcher-opened SQLite connection"
        )
    binding = _AnonymousScratchBinding(
        pre_dispatch_context_sha256=_pre_dispatch_context_sha256(
            contract,
            controller_phase_audits,
        ),
        controller_registered_scratch_bytes_checkpoint_maximum=(
            contract.resource_limits.controller_registered_scratch_bytes_checkpoint_maximum
        ),
        members=tuple(members),
        anonymous_scratch_creation_isolation_verified=False,
        sqlite_connection=sqlite_connection,
    )
    try:
        return _mint_anonymous_scratch_capability(binding)
    except BaseException:
        _close_anonymous_scratch_binding(binding)
        raise


def _test_only_prepare_day1b_expected_f1m_registry(
    *,
    contract: Day1BWorkerProtocolContract,
    controller_phase_audits: tuple[Day1BWorkerPhaseAudit, ...],
    window_cardinalities: Iterable[Day1BF1MWindowCardinality],
    window_batches: Iterable[Day1BF1MWindowBatch],
    expected_f1m_objects: Iterable[Day1BControllerExpectedF1MObject],
    controlled_scratch_root: Path,
) -> Day1BExpectedF1MRegistryCapability:
    """Build private non-authorizing size-class evidence for protocol fixtures."""

    _require_test_invocation_issuer()
    if type(contract) is not Day1BWorkerProtocolContract:
        raise TypeError("contract must be an exact Day1BWorkerProtocolContract")
    _validate_controller_phase_audits(contract, controller_phase_audits)
    scratch_capability = _test_only_issue_day1b_anonymous_scratch_capability(
        contract=contract,
        controller_phase_audits=controller_phase_audits,
        controlled_scratch_root=controlled_scratch_root,
    )
    scratch = _ControlledScratch(
        scratch_capability,
        contract=contract,
        controller_phase_audits=controller_phase_audits,
    )
    registry = _ExpectedF1MRegistry(
        scratch,
        contract=contract,
        controller_phase_audits=controller_phase_audits,
        window_cardinalities=window_cardinalities,
        window_batches=window_batches,
        expected_f1m_objects=expected_f1m_objects,
    )
    try:
        return _mint_expected_registry_capability(registry)
    except BaseException:
        with suppress(BaseException):
            registry.close()
        raise


class _ObjectReceiptSpool:
    """Controlled disk metadata plus expected weighted F1-M size-class matching."""

    def __init__(
        self,
        contract: Day1BWorkerProtocolContract,
        registry: _ExpectedF1MRegistry,
    ) -> None:
        self._contract = contract
        self._limits = contract.resource_limits
        self._scratch, self._digests = registry.transfer_to_spool()
        self._file: BinaryIO | None = None
        try:
            self._file = self._scratch.create_binary_file("object-receipts.jsonl")
            self._digests.commit()
            self._scratch.require_within_cap()
        except BaseException:
            with suppress(BaseException):
                self._digests.close()
            if self._file is not None:
                with suppress(BaseException):
                    self._file.close()
            self._scratch.close()
            raise
        assert self._file is not None
        self._observed_f1m_size_class_count = 0
        self._hasher = hashlib.sha256()
        self.object_count = 0
        self.line_count = 0
        self.byte_count = 0
        self.payload_byte_count = 0
        self._sealed = False
        self._closed = False
        self._close_lock = threading.Lock()

    def write(
        self,
        *,
        candidate_id: str,
        phase: str,
        category: str,
        transaction: str,
        receipt: _Day1BWorkerSerializedObjectReceipt,
        retain: bool,
    ) -> bytes | None:
        if self._sealed or self._closed:
            raise Day1BWorkerProtocolError("worker object receipt spool is not writable")
        if self.object_count >= self._limits.serialized_object_receipt_count_maximum:
            raise Day1BWorkerProtocolError("serialized-object receipt count exceeds frozen cap")
        next_payload_bytes = self.payload_byte_count + receipt.serialized_byte_count
        if next_payload_bytes > self._limits.serialized_payload_bytes_per_cell_maximum:
            raise Day1BWorkerProtocolError("serialized payload bytes exceed frozen cell cap")
        if receipt.f1m_size_class is not None:
            size_class_sha256 = hashlib.sha256(
                _canonical_json_bytes(receipt.f1m_size_class.to_document())
            ).hexdigest()
            updated = self._digests.execute(
                "UPDATE expected_f1m SET observed=1 "
                "WHERE phase=? AND category=? AND object_ordinal=? "
                "AND size_class_sha256=? AND multiplicity=? AND observed=0",
                (
                    phase,
                    category,
                    receipt.serialization_equivalence_class_ordinal,
                    size_class_sha256,
                    receipt.multiplicity,
                ),
            )
            if updated.rowcount != 1:
                raise Day1BWorkerProtocolError(
                    "worker F1-M object does not match one unconsumed "
                    "controller expected weighted size class"
                )
            self._observed_f1m_size_class_count += 1
            self._digests.commit()
        self.object_count += 1
        self.payload_byte_count = next_payload_bytes
        if not retain:
            self._scratch.require_within_cap()
            return None
        line = _canonical_json_bytes(
            {
                "schema_version": "dynamic-cssc-publication-day1b-object-receipt-v1",
                "candidate_id": candidate_id,
                "category": category,
                "worker_input_binding_sha256": self._contract.input_binding_sha256,
                "object": receipt.to_document(),
                "phase": phase,
                "spool_line_ordinal": self.line_count,
                "transaction": transaction,
            }
        )
        if len(line) > DAY1B_AGGREGATE_RECEIPT_CANONICAL_BYTES_MAXIMUM:
            raise Day1BWorkerProtocolError(
                "canonical serialized-object receipt exceeds frozen 2 KiB bound"
            )
        if self.byte_count + len(line) > (
            self._limits.serialized_object_receipt_spool_bytes_maximum
        ):
            raise Day1BWorkerProtocolError("serialized-object receipt spool exceeds frozen cap")
        self._file.write(line)
        self._file.flush()
        self._hasher.update(line)
        self.line_count += 1
        self.byte_count += len(line)
        self._scratch.require_within_cap()
        return line

    def seal(
        self,
        *,
        required_observed_f1m_phases: tuple[str, ...],
    ) -> tuple[str, int, int]:
        if self._closed:
            raise Day1BWorkerProtocolError("worker object receipt spool is closed")
        if type(required_observed_f1m_phases) is not tuple or any(
            type(phase) is not str or phase not in _PHASE_NAMES
            for phase in required_observed_f1m_phases
        ):
            raise Day1BWorkerProtocolError("required observed F1-M phases are not a closed tuple")
        if required_observed_f1m_phases:
            placeholders = ",".join("?" for _phase in required_observed_f1m_phases)
            missing = self._digests.execute(
                f"SELECT COUNT(*) FROM expected_f1m WHERE observed=0 AND phase IN ({placeholders})",
                required_observed_f1m_phases,
            ).fetchone()
            if missing is None or type(missing[0]) is not int or missing[0] != 0:
                raise Day1BWorkerProtocolError(
                    "controller expected F1-M size classes for a complete phase remain unobserved"
                )
        self._sealed = True
        self._file.flush()
        self._scratch.require_within_cap()
        return self._hasher.hexdigest(), self.line_count, self.byte_count

    @property
    def observed_f1m_size_class_count(self) -> int:
        return self._observed_f1m_size_class_count

    @property
    def controller_registered_scratch_peak_bytes(self) -> int:
        return self._scratch.peak_bytes

    def copy_to(self, destination: BinaryIO) -> str:
        if not self._sealed or self._closed:
            raise Day1BWorkerProtocolError("worker object receipt spool is not sealed")
        if not callable(getattr(destination, "write", None)):
            raise TypeError("object receipt destination must be a binary writable stream")
        if not all(
            callable(getattr(destination, operation, None))
            for operation in ("flush", "read", "seek", "tell", "write")
        ):
            raise TypeError("object receipt destination must be a readable seekable binary stream")
        destination.seek(0, os.SEEK_END)
        if destination.tell() != 0:
            raise Day1BWorkerProtocolError("object receipt destination must be empty")
        destination.seek(0)
        self._file.seek(0)
        observed_count = 0
        observed_bytes = 0
        observed_hasher = hashlib.sha256()
        while line := self._file.readline():
            observed_count += 1
            observed_bytes += len(line)
            observed_hasher.update(line)
            written = destination.write(line)
            if type(written) is not int or written != len(line):
                raise Day1BWorkerProtocolError(
                    "object receipt destination did not accept one complete line"
                )
        if (
            observed_count != self.line_count
            or observed_bytes != self.byte_count
            or observed_hasher.hexdigest() != self._hasher.hexdigest()
        ):
            raise Day1BWorkerProtocolError("worker object receipt spool changed after sealing")
        destination.flush()
        destination.seek(0)
        copied_hasher = hashlib.sha256()
        copied_bytes = 0
        while block := destination.read(1024 * 1024):
            if type(block) is not bytes:
                raise Day1BWorkerProtocolError(
                    "object receipt destination did not return exact bytes"
                )
            copied_hasher.update(block)
            copied_bytes += len(block)
        if copied_bytes != self.byte_count or copied_hasher.hexdigest() != self._hasher.hexdigest():
            raise Day1BWorkerProtocolError(
                "object receipt destination differs after complete rehash"
            )
        return copied_hasher.hexdigest()

    def close(self) -> None:
        with self._close_lock:
            if self._closed:
                return
            database_error: BaseException | None = None
            file_error: BaseException | None = None
            scratch_error: BaseException | None = None
            try:
                self._digests.close()
            except BaseException as error:  # pragma: no cover - defensive cleanup
                database_error = error
            finally:
                try:
                    self._file.close()
                except BaseException as error:  # pragma: no cover - defensive cleanup
                    file_error = error
                finally:
                    try:
                        self._scratch.close()
                    except BaseException as error:  # pragma: no cover - diagnostic retention
                        scratch_error = error
            self._closed = True
            if scratch_error is not None:
                raise scratch_error
            if file_error is not None:
                raise Day1BWorkerProtocolError(
                    "controlled scratch spool could not be closed"
                ) from file_error
            if database_error is not None:
                raise Day1BWorkerProtocolError(
                    "controlled scratch index could not be closed"
                ) from database_error


@dataclass(frozen=True, slots=True)
class _InvocationBinding:
    contract_input_binding_sha256: str
    invocation_id: str
    candidate_id: str
    controller_phase_audits: tuple[Day1BWorkerPhaseAudit, ...]
    observation: _ControllerCandidateObservation
    expected_registry_descriptor: Day1BExpectedF1MRegistryDescriptor
    spool: _ObjectReceiptSpool


class Day1BWorkerInvocationCapability:
    """Opaque single-use process observation minted by a launcher."""

    __slots__ = ("_binding", "__weakref__")

    def __new__(cls) -> Day1BWorkerInvocationCapability:
        raise TypeError("Day1B worker invocation capabilities are launcher-minted")

    def __bool__(self) -> bool:
        raise TypeError("Day1B worker invocation evidence is not a caller boolean")


def _collected_invocation(identifier: int) -> None:
    with _INVOCATION_LOCK:
        active = _ISSUED_INVOCATIONS.pop(identifier, None)
    if active is not None:
        binding = active[1]
        assert type(binding) is _InvocationBinding
        binding.spool.close()


def _mint_invocation_capability(
    binding: _InvocationBinding,
) -> Day1BWorkerInvocationCapability:
    capability = object.__new__(Day1BWorkerInvocationCapability)
    object.__setattr__(capability, "_binding", binding)
    identifier = id(capability)
    reference = weakref.ref(
        capability,
        lambda _reference, identifier=identifier: _collected_invocation(identifier),
    )
    with _INVOCATION_LOCK:
        _ISSUED_INVOCATIONS[identifier] = (reference, binding)
    return capability


def _require_test_invocation_issuer() -> None:
    current = os.environ.get("PYTEST_CURRENT_TEST", "")
    allowed_callers = (
        (
            "tests/test_publication_day1b_worker_protocol.py::",
            "/tests/test_publication_day1b_worker_protocol.py",
        ),
        (
            "tests/test_publication_day1b.py::",
            "/tests/test_publication_day1b.py",
        ),
    )
    expected_path = next(
        (path for prefix, path in allowed_callers if current.startswith(prefix)),
        None,
    )
    stack_matches = expected_path is not None and any(
        Path(frame.filename).as_posix().endswith(expected_path) for frame in inspect.stack()
    )
    if not stack_matches:
        raise Day1BWorkerProtocolError("private Day1B invocation fixture issuer is pytest-only")


def _test_only_issue_day1b_worker_invocation(
    *,
    contract: Day1BWorkerProtocolContract,
    controller_phase_audits: tuple[Day1BWorkerPhaseAudit, ...],
    expected_f1m_registry_capability: Day1BExpectedF1MRegistryCapability,
    elapsed_ns: int,
    peak_resident_memory_bytes: int,
    peak_scratch_bytes: int,
    terminal_failure_code: str | None,
) -> Day1BWorkerInvocationCapability:
    """Mint non-production fixture evidence for one weighted candidate cell."""

    _require_test_invocation_issuer()
    if type(contract) is not Day1BWorkerProtocolContract:
        raise TypeError("contract must be an exact Day1BWorkerProtocolContract")
    _validate_controller_phase_audits(contract, controller_phase_audits)
    registry = _active_expected_registry_binding(
        expected_f1m_registry_capability,
        consume=True,
    ).registry
    descriptor = registry.descriptor
    try:
        if (
            descriptor.size_class_set_sha256 != contract.expected_f1m_size_class_set_sha256
            or descriptor.size_class_count != contract.expected_f1m_size_class_count
        ):
            raise Day1BWorkerProtocolError(
                "fixture size-class expectation differs from the worker input binding"
            )
        registry.validate_for_invocation(contract, controller_phase_audits)
        limits = contract.resource_limits
        expected_all = contract.expected_serialized_equivalence_class_count
        if expected_all > limits.serialized_object_receipt_count_maximum:
            raise Day1BWorkerProtocolError(
                "all serialized equivalence classes exceed the receipt count cap"
            )
        if expected_all + 7 > limits.worker_frame_count_maximum:
            raise Day1BWorkerProtocolError(
                "all serialized equivalence classes plus seven control frames "
                "exceed the frame count cap"
            )
        observation = _ControllerCandidateObservation(
            candidate_id=contract.candidate.candidate_id,
            elapsed_ns=elapsed_ns,
            peak_resident_memory_bytes=peak_resident_memory_bytes,
            peak_scratch_bytes=peak_scratch_bytes,
            terminal_failure_code=terminal_failure_code,
        )
        spool = _ObjectReceiptSpool(contract, registry)
    except BaseException:
        registry.close()
        raise
    binding = _InvocationBinding(
        contract_input_binding_sha256=contract.input_binding_sha256,
        invocation_id=contract.invocation_id,
        candidate_id=contract.candidate.candidate_id,
        controller_phase_audits=controller_phase_audits,
        observation=observation,
        expected_registry_descriptor=descriptor,
        spool=spool,
    )
    try:
        return _mint_invocation_capability(binding)
    except BaseException:
        with suppress(BaseException):
            spool.close()
        raise


def _claim_invocation(
    capability: Day1BWorkerInvocationCapability,
    contract: Day1BWorkerProtocolContract,
) -> _InvocationBinding:
    if type(capability) is not Day1BWorkerInvocationCapability:
        raise TypeError("invocation capability must be exact launcher-minted evidence")
    with _INVOCATION_LOCK:
        active = _ISSUED_INVOCATIONS.pop(id(capability), None)
    binding = _require_popped_authoritative_binding(
        active,
        capability=capability,
        presented=getattr(capability, "_binding", None),
        binding_type=_InvocationBinding,
        cleanup=lambda value: value.spool.close(),
        error_message="Day1B invocation capability is absent, unissued, or consumed",
    )
    assert type(binding) is _InvocationBinding
    if (
        binding.contract_input_binding_sha256 != contract.input_binding_sha256
        or binding.invocation_id != contract.invocation_id
        or binding.candidate_id != contract.candidate.candidate_id
    ):
        binding.spool.close()
        raise Day1BWorkerProtocolError(
            "Day1B invocation capability does not match this input binding"
        )
    return binding


def abandon_day1b_worker_invocation(
    capability: Day1BWorkerInvocationCapability,
) -> None:
    """Consume an unused launcher capability and clean its controlled scratch."""

    if type(capability) is not Day1BWorkerInvocationCapability:
        raise TypeError("invocation capability must be exact launcher-minted evidence")
    with _INVOCATION_LOCK:
        active = _ISSUED_INVOCATIONS.pop(id(capability), None)
    binding = _require_popped_authoritative_binding(
        active,
        capability=capability,
        presented=getattr(capability, "_binding", None),
        binding_type=_InvocationBinding,
        cleanup=lambda value: value.spool.close(),
        error_message="Day1B invocation capability is absent or consumed",
    )
    assert type(binding) is _InvocationBinding
    binding.spool.close()


@dataclass(frozen=True, slots=True)
class _EvidenceBinding:
    receipt: Day1BWorkerCellReceipt
    spool: _ObjectReceiptSpool


class Day1BWorkerEvidenceCapability:
    """Opaque single-use capability minted only by the streaming decoder."""

    __slots__ = ("_binding", "__weakref__")

    def __new__(cls) -> Day1BWorkerEvidenceCapability:
        raise TypeError("Day1B worker evidence capabilities are decoder-minted")

    def __bool__(self) -> bool:
        raise TypeError("Day1B worker evidence is not a caller-supplied boolean")


class Day1BClaimedWorkerEvidence:
    """Claimed receipt plus its still descriptor-backed metadata spool."""

    __slots__ = ("_binding", "_closed", "_finalizer", "__weakref__")

    def __new__(cls, token: object, binding: _EvidenceBinding) -> Day1BClaimedWorkerEvidence:
        if token is not _EVIDENCE_TOKEN:
            raise TypeError("claimed Day1B worker evidence is decoder-minted")
        instance = super().__new__(cls)
        instance._binding = binding
        instance._closed = False
        instance._finalizer = weakref.finalize(instance, binding.spool.close)
        return instance

    @property
    def receipt(self) -> Day1BWorkerCellReceipt:
        self._require_open()
        return self._binding.receipt

    @property
    def object_receipt_line_count(self) -> int:
        return self.receipt.object_receipt_line_count

    def copy_object_receipts_to(self, destination: BinaryIO) -> str:
        """Copy and fully revalidate the sealed spool before reporting success."""

        self._require_open()
        return self._binding.spool.copy_to(destination)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._finalizer()

    def _require_open(self) -> None:
        if self._closed:
            raise Day1BWorkerProtocolError("claimed Day1B worker evidence is closed")

    def __enter__(self) -> Day1BClaimedWorkerEvidence:
        self._require_open()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def claim_day1b_worker_evidence(
    capability: Day1BWorkerEvidenceCapability,
) -> Day1BClaimedWorkerEvidence:
    """Consume one decoder-minted capability and expose its receipt/spool once."""

    if type(capability) is not Day1BWorkerEvidenceCapability:
        raise TypeError("capability must be exact decoder-minted Day1B worker evidence")
    with _EVIDENCE_LOCK:
        active = _ISSUED_EVIDENCE.pop(id(capability), None)
    binding = _require_popped_authoritative_binding(
        active,
        capability=capability,
        presented=getattr(capability, "_binding", None),
        binding_type=_EvidenceBinding,
        cleanup=lambda value: value.spool.close(),
        error_message="Day1B worker evidence capability is absent or consumed",
    )
    assert type(binding) is _EvidenceBinding
    try:
        return Day1BClaimedWorkerEvidence(_EVIDENCE_TOKEN, binding)
    except BaseException:
        with suppress(BaseException):
            binding.spool.close()
        raise


def abandon_day1b_worker_evidence(
    capability: Day1BWorkerEvidenceCapability,
) -> None:
    """Consume unclaimed decoder evidence and clean its controlled scratch."""

    if type(capability) is not Day1BWorkerEvidenceCapability:
        raise TypeError("capability must be exact decoder-minted Day1B worker evidence")
    with _EVIDENCE_LOCK:
        active = _ISSUED_EVIDENCE.pop(id(capability), None)
    binding = _require_popped_authoritative_binding(
        active,
        capability=capability,
        presented=getattr(capability, "_binding", None),
        binding_type=_EvidenceBinding,
        cleanup=lambda value: value.spool.close(),
        error_message="Day1B worker evidence capability is absent or consumed",
    )
    assert type(binding) is _EvidenceBinding
    binding.spool.close()


def _counts(value: object, expected: int, field: str) -> tuple[int, ...]:
    if type(value) is not list or len(value) != expected:
        raise Day1BWorkerProtocolError(f"{field} must cover the exact primitive vocabulary")
    return tuple(_strict_nonnegative(item, field) for item in value)


def _controller_limit_failure_code(
    limits: Day1BWorkerResourceLimits,
    observation: _ControllerCandidateObservation,
) -> str | None:
    if observation.elapsed_ns > limits.wall_clock_ns_per_candidate_cell:
        return "wall-clock-limit-exceeded"
    if observation.peak_resident_memory_bytes > limits.resident_memory_bytes_per_candidate_cell:
        return "resident-memory-limit-exceeded"
    if observation.peak_scratch_bytes > limits.scratch_bytes_per_candidate_cell:
        return "scratch-limit-exceeded"
    return None


def _validate_controller_phase_audits(
    contract: Day1BWorkerProtocolContract,
    controller_phase_audits: tuple[Day1BWorkerPhaseAudit, ...],
) -> None:
    if (
        type(controller_phase_audits) is not tuple
        or len(controller_phase_audits) != len(_AUDIT_PHASE_NAMES)
        or any(type(item) is not Day1BWorkerPhaseAudit for item in controller_phase_audits)
    ):
        raise Day1BWorkerProtocolError("controller phase audit tuple is not exact")
    for index, (audit, expected_range) in enumerate(
        zip(controller_phase_audits, contract.phase_ranges, strict=True)
    ):
        if (
            audit.phase != _AUDIT_PHASE_NAMES[index]
            or audit.accepted_group_start != expected_range.accepted_group_start
            or audit.accepted_group_end != expected_range.accepted_group_end
        ):
            raise Day1BWorkerProtocolError("controller phase audit range is not exact")


class _CategoryAccumulator:
    __slots__ = (
        "charged_byte_count",
        "equivalence_class_count",
        "object_receipt_hasher",
        "protocol_object_count",
        "spool_line_count",
        "spool_start_line",
    )

    def __init__(self, spool_start_line: int) -> None:
        self.charged_byte_count = 0
        self.equivalence_class_count = 0
        self.object_receipt_hasher = hashlib.sha256()
        self.protocol_object_count = 0
        self.spool_line_count = 0
        self.spool_start_line = spool_start_line

    def add(
        self,
        receipt: _Day1BWorkerSerializedObjectReceipt,
        line: bytes | None,
        *,
        spool_line: int,
    ) -> None:
        self.charged_byte_count += receipt.charged_byte_count
        self.equivalence_class_count += 1
        self.protocol_object_count += receipt.multiplicity
        if line is not None:
            if self.spool_line_count == 0:
                self.spool_start_line = spool_line
            self.spool_line_count += 1
            self.object_receipt_hasher.update(line)


class _ReceiptBuilder:
    def __init__(
        self,
        contract: Day1BWorkerProtocolContract,
        spool: _ObjectReceiptSpool,
        controller_candidate_observation: _ControllerCandidateObservation,
        expected_registry_descriptor: Day1BExpectedF1MRegistryDescriptor,
    ) -> None:
        self.contract = contract
        self.spool = spool
        self.controller_candidate_observation = controller_candidate_observation
        self.expected_registry_descriptor = expected_registry_descriptor
        self.started = False
        self.ended = False
        self.current_spec: Day1BWorkerCandidateSpec | None = None
        self.current_phase_index = 0
        self.current_categories: list[_CategoryAccumulator] = []
        self.last_category_index = -1
        self.current_phases: list[Day1BWorkerPhaseReceipt] = []
        self.completed_candidate: Day1BWorkerCandidateReceipt | None = None

    def accept(self, header: dict[str, object], payload_sha256: str | None) -> None:
        kind = header["frame_kind"]
        if self.ended:
            raise Day1BWorkerProtocolError("trailing worker frame follows cell-end")
        if kind == "cell-start":
            self._cell_start(header)
        elif kind == "candidate-start":
            self._candidate_start(header)
        elif kind == "serialized-object":
            self._serialized_object(header, payload_sha256)
        elif kind == "phase-result":
            self._phase_result(header)
        elif kind == "candidate-result":
            self._candidate_result(header)
        elif kind == "cell-end":
            self._cell_end(header)
        else:  # pragma: no cover - checked by frame validation
            raise Day1BWorkerProtocolError("worker frame kind is not frozen")

    def _cell_start(self, header: dict[str, object]) -> None:
        if self.started or _canonical_json_bytes(header["input_binding"]) != (
            _canonical_json_bytes(self.contract.input_binding_document())
        ):
            raise Day1BWorkerProtocolError("worker input binding is not exact")
        self.started = True

    def _candidate_start(self, header: dict[str, object]) -> None:
        if (
            not self.started
            or self.current_spec is not None
            or self.completed_candidate is not None
        ):
            raise Day1BWorkerProtocolError("worker candidate boundary is out of order")
        spec = self.contract.candidate
        if (header["candidate_id"], header["candidate_role"]) != (
            spec.candidate_id,
            spec.candidate_role,
        ):
            raise Day1BWorkerProtocolError("worker candidate order or role changed")
        self.current_spec = spec
        self.current_phase_index = 0
        self.current_categories = [
            _CategoryAccumulator(self.spool.line_count)
            for _category in self.contract.serialized_categories
        ]
        self.last_category_index = -1
        self.current_phases = []

    def _expected_phase(self) -> str:
        if self.current_spec is None or self.current_phase_index >= len(_PHASE_NAMES):
            raise Day1BWorkerProtocolError("worker phase boundary is out of order")
        return _PHASE_NAMES[self.current_phase_index]

    def _require_candidate_phase(self, header: dict[str, object]) -> tuple[str, str]:
        expected_phase = self._expected_phase()
        assert self.current_spec is not None
        if header["candidate_id"] != self.current_spec.candidate_id:
            raise Day1BWorkerProtocolError("worker frame candidate identity changed")
        if header["phase"] != expected_phase:
            raise Day1BWorkerProtocolError("worker phase order is not warmup/tuning/heldout")
        return self.current_spec.candidate_id, expected_phase

    def _serialized_object(
        self,
        header: dict[str, object],
        payload_sha256: str | None,
    ) -> None:
        _candidate_id, phase = self._require_candidate_phase(header)
        assert self.current_spec is not None
        if phase not in self.current_spec.retained_phases:
            raise Day1BWorkerProtocolError("non-retained worker phase emitted partial quantities")
        category = header["category"]
        category_names = tuple(item[0] for item in self.contract.serialized_categories)
        if type(category) is not str or category not in category_names:
            raise Day1BWorkerProtocolError("serialized-object category is not frozen")
        category_index = category_names.index(category)
        if category_index < self.last_category_index:
            raise Day1BWorkerProtocolError("serialized-object category order changed")
        ordinal = _strict_nonnegative(header["object_ordinal"], "object_ordinal")
        accumulator = self.current_categories[category_index]
        if ordinal != accumulator.equivalence_class_count:
            raise Day1BWorkerProtocolError("serialized-object object ordinal is not contiguous")
        multiplicity = _strict_positive(header["multiplicity"], "multiplicity")
        byte_count = _strict_positive(header["payload_byte_count"], "payload_byte_count")
        if payload_sha256 is None:
            raise Day1BWorkerProtocolError("serialized-object payload digest is absent")
        f1m_size_class_required = category in self.contract.f1m_size_class_categories
        raw_f1m_size_class = header["f1m_size_class"]
        if f1m_size_class_required:
            f1m_size_class = Day1BF1MSizeClass.from_document(raw_f1m_size_class)
            expected_kind = (
                "random-zero-sum"
                if category == "query-f1m-random-mask-ciphertexts"
                else "encrypted-zero-dummy"
            )
            if f1m_size_class.f1m_kind != expected_kind:
                raise Day1BWorkerProtocolError(
                    "F1-M size-class kind does not match serialized category"
                )
        else:
            if raw_f1m_size_class is not None:
                raise Day1BWorkerProtocolError(
                    "non-F1-M serialized category cannot carry an F1-M size class"
                )
            f1m_size_class = None
        transaction = self.contract.serialized_categories[category_index][1]
        if transaction == "one-time" and phase != self.current_spec.retained_phases[0]:
            raise Day1BWorkerProtocolError(
                "one-time inventory is only reported in the first retained phase"
            )
        receipt = _Day1BWorkerSerializedObjectReceipt(
            serialization_equivalence_class_ordinal=ordinal,
            serialized_byte_count=byte_count,
            serialized_sha256=payload_sha256,
            multiplicity=multiplicity,
            charged_byte_count=byte_count * multiplicity,
            f1m_size_class=f1m_size_class,
        )
        spool_line = self.spool.line_count
        line = self.spool.write(
            candidate_id=self.current_spec.candidate_id,
            phase=phase,
            category=category,
            transaction=transaction,
            receipt=receipt,
            retain=True,
        )
        accumulator.add(receipt, line, spool_line=spool_line)
        self.last_category_index = category_index

    def _phase_result(self, header: dict[str, object]) -> None:
        _candidate_id, phase = self._require_candidate_phase(header)
        assert self.current_spec is not None
        retained = header["retained_measurement"]
        expected_retained = phase in self.current_spec.retained_phases
        if type(retained) is not bool or retained is not expected_retained:
            raise Day1BWorkerProtocolError("worker retained-measurement phase role changed")
        audit = Day1BWorkerPhaseAudit.from_document(header["phase_audit"])
        expected_audit_phase = _AUDIT_PHASE_NAMES[self.current_phase_index]
        expected_range = self.contract.phase_ranges[self.current_phase_index]
        if (
            audit.phase != expected_audit_phase
            or audit.accepted_group_start != expected_range.accepted_group_start
            or audit.accepted_group_end != expected_range.accepted_group_end
        ):
            raise Day1BWorkerProtocolError("worker phase audit range changed")
        outcome = header["outcome"]
        failure_code = header["failure_code"]
        if type(outcome) is not str or (failure_code is not None and type(failure_code) is not str):
            raise Day1BWorkerProtocolError("worker phase outcome/code enum is not a string")
        object_counts = header["serialized_category_object_counts"]
        if not retained:
            if (
                header["update_primitive_counts"] is not None
                or header["query_primitive_counts"] is not None
                or object_counts is not None
                or any(item.equivalence_class_count for item in self.current_categories)
            ):
                raise Day1BWorkerProtocolError(
                    "non-retained worker phase must discard all measurement quantities"
                )
            if outcome == "complete":
                if failure_code is not None:
                    raise Day1BWorkerProtocolError(
                        "complete non-retained worker phase carries a failure code"
                    )
            elif not (outcome == "failed" and failure_code == "candidate-execution-failed"):
                raise Day1BWorkerProtocolError(
                    "worker phase may only self-report candidate-execution-failed; "
                    "timeout, infeasible, and missing are controller-only"
                )
            update_counts = None
            query_counts = None
            categories = None
        elif outcome == "complete":
            if failure_code is not None:
                raise Day1BWorkerProtocolError("complete worker phase carries a failure code")
            update_counts = _counts(
                header["update_primitive_counts"],
                len(self.contract.primitive_names),
                "update_primitive_counts",
            )
            query_counts = _counts(
                header["query_primitive_counts"],
                len(self.contract.primitive_names),
                "query_primitive_counts",
            )
            parsed_object_counts = _counts(
                object_counts,
                len(self.contract.serialized_categories),
                "serialized_category_object_counts",
            )
            if parsed_object_counts != tuple(
                item.equivalence_class_count for item in self.current_categories
            ):
                raise Day1BWorkerProtocolError(
                    "serialized category object counts do not match streamed payloads"
                )
            if bool(audit.realized_query_count) != any(query_counts):
                raise Day1BWorkerProtocolError(
                    "query primitive vector does not match controller-realized query presence"
                )
            categories = tuple(
                Day1BWorkerSerializedCategoryReceipt(
                    category=category,
                    transaction=transaction,
                    serialization_equivalence_class_count=(accumulator.equivalence_class_count),
                    protocol_object_count=accumulator.protocol_object_count,
                    charged_byte_count=accumulator.charged_byte_count,
                    object_receipt_stream_sha256=(accumulator.object_receipt_hasher.hexdigest()),
                    object_receipt_spool_start_line=accumulator.spool_start_line,
                    object_receipt_spool_line_count=accumulator.spool_line_count,
                )
                for (category, transaction), accumulator in zip(
                    self.contract.serialized_categories,
                    self.current_categories,
                    strict=True,
                )
            )
        elif outcome == "failed":
            if (
                failure_code != "candidate-execution-failed"
                or header["update_primitive_counts"] is not None
                or header["query_primitive_counts"] is not None
                or object_counts is not None
                or any(item.equivalence_class_count for item in self.current_categories)
            ):
                raise Day1BWorkerProtocolError(
                    "failed worker phase must use a closed code and discard partial quantities"
                )
            update_counts = None
            query_counts = None
            categories = None
        else:
            raise Day1BWorkerProtocolError(
                "worker phase outcome must be complete or worker failed; "
                "terminal taxonomy is controller-only"
            )
        self.current_phases.append(
            Day1BWorkerPhaseReceipt(
                phase=phase,
                retained_measurement=retained,
                outcome=outcome,
                failure_code=failure_code,
                update_primitive_counts=update_counts,
                query_primitive_counts=query_counts,
                serialized_categories=categories,
                worker_declared_phase_audit=audit,
            )
        )
        self.current_phase_index += 1
        self.current_categories = [
            _CategoryAccumulator(self.spool.line_count)
            for _category in self.contract.serialized_categories
        ]
        self.last_category_index = -1

    def _candidate_result(self, header: dict[str, object]) -> None:
        if self.current_spec is None or self.current_phase_index != len(_PHASE_NAMES):
            raise Day1BWorkerProtocolError("worker candidate ended before all three phases")
        if header["candidate_id"] != self.current_spec.candidate_id:
            raise Day1BWorkerProtocolError("worker candidate result identity changed")
        elapsed = _strict_nonnegative(header["elapsed_ns"], "elapsed_ns")
        resident = _strict_nonnegative(
            header["peak_resident_memory_bytes"], "peak_resident_memory_bytes"
        )
        scratch = _strict_nonnegative(header["peak_scratch_bytes"], "peak_scratch_bytes")
        retry = _strict_nonnegative(header["candidate_retry_count"], "candidate_retry_count")
        reset = _strict_nonnegative(header["state_reset_count"], "state_reset_count")
        if retry != 0:
            raise Day1BWorkerProtocolError("candidate selective retry is forbidden")
        if reset != 0:
            raise Day1BWorkerProtocolError("worker-declared candidate state reset is forbidden")
        observation = self.controller_candidate_observation
        if (
            observation.candidate_id != self.current_spec.candidate_id
            or observation.elapsed_ns != elapsed
            or observation.peak_resident_memory_bytes != resident
            or observation.peak_scratch_bytes != scratch
        ):
            raise Day1BWorkerProtocolError(
                "worker resource report differs from controller-owned observations"
            )
        if observation.terminal_failure_code is not None:
            raise Day1BWorkerProtocolError(
                "controller-terminal candidate cannot also carry a worker transcript"
            )
        phases = tuple(self.current_phases)
        incomplete_seen = False
        for phase in phases:
            if incomplete_seen and phase.outcome == "complete":
                raise Day1BWorkerProtocolError(
                    "candidate cannot complete after an earlier phase failure"
                )
            incomplete_seen = incomplete_seen or phase.outcome != "complete"
        self.completed_candidate = Day1BWorkerCandidateReceipt(
            candidate_id=self.current_spec.candidate_id,
            candidate_role=self.current_spec.candidate_role,
            phases=phases,
            elapsed_ns=observation.elapsed_ns,
            peak_resident_memory_bytes=observation.peak_resident_memory_bytes,
            peak_scratch_bytes=observation.peak_scratch_bytes,
            candidate_retry_count=retry,
            worker_declared_state_reset_count=reset,
            terminal_outcome=None,
            terminal_failure_code=None,
            receipt_origin="worker-complete-transcript",
        )
        self.current_spec = None
        self.current_phases = []
        self.current_categories = []

    def _cell_end(self, header: dict[str, object]) -> None:
        candidate_count = _strict_nonnegative(header["candidate_count"], "candidate_count")
        if (
            not self.started
            or self.current_spec is not None
            or self.completed_candidate is None
            or candidate_count != 1
        ):
            raise Day1BWorkerProtocolError("worker cell ended with incomplete candidate coverage")
        self.ended = True

    def finish(
        self,
        controller_phase_audits: tuple[Day1BWorkerPhaseAudit, ...],
    ) -> Day1BWorkerCellReceipt:
        if not self.ended:
            raise Day1BWorkerProtocolError("worker transcript is truncated before cell-end")
        _validate_controller_phase_audits(self.contract, controller_phase_audits)
        assert self.completed_candidate is not None
        observed = tuple(
            phase.worker_declared_phase_audit for phase in self.completed_candidate.phases
        )
        if observed != controller_phase_audits:
            raise Day1BWorkerProtocolError(
                "worker phase audit differs from the controller-owned audit"
            )
        spool_sha256, spool_line_count, spool_byte_count = self.spool.seal(
            required_observed_f1m_phases=tuple(
                phase.phase
                for phase in self.completed_candidate.phases
                if phase.outcome == "complete"
            )
        )
        expected_all_count = self.contract.expected_serialized_equivalence_class_count
        all_phases_complete = all(
            phase.outcome == "complete" for phase in self.completed_candidate.phases
        )
        if spool_line_count > expected_all_count or (
            all_phases_complete and spool_line_count != expected_all_count
        ):
            raise Day1BWorkerProtocolError(
                "worker all serialized equivalence class count differs from the "
                "controller-owned pre-dispatch count"
            )
        return Day1BWorkerCellReceipt(
            input_binding=self.contract,
            f1m_controller_context_sha256=(self.contract.f1m_controller_context_sha256),
            f1m_route_coverage_sha256=self.contract.f1m_route_coverage_sha256,
            f1m_charged_size_class_set_sha256=(self.contract.f1m_charged_size_class_set_sha256),
            candidate=self.completed_candidate,
            controller_schedule_phase_audits=controller_phase_audits,
            worker_declared_phase_audits_match_controller_schedule_audits=True,
            runtime_state_continuity_verified=False,
            controller_expected_f1m_size_class_set_sha256=(
                self.contract.expected_f1m_size_class_set_sha256
            ),
            controller_expected_f1m_size_class_count=(self.contract.expected_f1m_size_class_count),
            controller_expected_f1m_phase_size_class_counts=(
                self.expected_registry_descriptor.phase_size_class_counts
            ),
            controller_expected_f1m_phase_query_counts=(
                self.expected_registry_descriptor.phase_query_counts
            ),
            controller_expected_f1m_phase_random_route_counts=(
                self.expected_registry_descriptor.phase_random_route_counts
            ),
            controller_expected_f1m_phase_dummy_route_counts=(
                self.expected_registry_descriptor.phase_dummy_route_counts
            ),
            controller_f1m_cardinality_derivation_root_sha256=(
                self.expected_registry_descriptor.cardinality_derivation_root_sha256
            ),
            controller_expected_serialized_equivalence_class_count=(
                self.contract.expected_serialized_equivalence_class_count
            ),
            worker_observed_f1m_size_class_count=self.spool.observed_f1m_size_class_count,
            worker_observed_f1m_materialized_binding_count=0,
            pre_dispatch_context_sha256=(
                self.expected_registry_descriptor.pre_dispatch_context_sha256
            ),
            controller_registered_scratch_bytes_checkpoint_maximum=(
                self.expected_registry_descriptor.controller_registered_scratch_bytes_checkpoint_maximum
            ),
            controller_observed_registered_scratch_peak_bytes=(
                self.spool.controller_registered_scratch_peak_bytes
            ),
            anonymous_scratch_creation_isolation_verified=(
                self.expected_registry_descriptor.anonymous_scratch_creation_isolation_verified
            ),
            controller_f1m_window_batch_stream_sha256=(
                self.expected_registry_descriptor.controller_f1m_window_batch_stream_sha256
            ),
            weighted_query_range_coverage_verified=(
                self.expected_registry_descriptor.weighted_query_range_coverage_verified
            ),
            production_execution_admissible=False,
            object_receipt_spool_sha256=spool_sha256,
            object_receipt_line_count=spool_line_count,
            object_receipt_byte_count=spool_byte_count,
        )


def _validate_frame_header(
    header: dict[str, object],
    *,
    expected_sequence: int,
    contract: Day1BWorkerProtocolContract,
) -> str:
    kind = header.get("frame_kind")
    if type(kind) is not str or kind not in _FRAME_KEYS:
        raise Day1BWorkerProtocolError("worker frame kind is not frozen")
    if set(header) != _FRAME_KEYS[kind]:
        raise Day1BWorkerProtocolError("worker frame keys are not exact")
    if header["schema_version"] != DAY1B_WORKER_FRAME_SCHEMA:
        raise Day1BWorkerProtocolError("worker frame schema is not frozen")
    sequence = _strict_nonnegative(header["sequence"], "sequence")
    if sequence != expected_sequence:
        raise Day1BWorkerProtocolError("worker frame sequence is not contiguous from zero")
    payload_count = _strict_nonnegative(header["payload_byte_count"], "payload_byte_count")
    if kind == "serialized-object":
        if payload_count <= 0:
            raise Day1BWorkerProtocolError("serialized-object payload must be nonempty")
        if payload_count > contract.resource_limits.serialized_object_bytes_maximum:
            raise Day1BWorkerProtocolError("serialized-object payload exceeds the frozen cap")
    elif payload_count != 0:
        raise Day1BWorkerProtocolError("control worker frames cannot carry a binary payload")
    return kind


def _mint_evidence_capability(
    receipt: Day1BWorkerCellReceipt,
    spool: _ObjectReceiptSpool,
) -> Day1BWorkerEvidenceCapability:
    binding = _EvidenceBinding(receipt=receipt, spool=spool)
    capability = object.__new__(Day1BWorkerEvidenceCapability)
    object.__setattr__(capability, "_binding", binding)
    identifier = id(capability)
    reference = weakref.ref(
        capability,
        lambda _reference, identifier=identifier: _collected_evidence(identifier),
    )
    with _EVIDENCE_LOCK:
        _ISSUED_EVIDENCE[identifier] = (reference, binding)
    return capability


def _collected_evidence(identifier: int) -> None:
    with _EVIDENCE_LOCK:
        active = _ISSUED_EVIDENCE.pop(identifier, None)
    if active is not None:
        binding = active[1]
        assert type(binding) is _EvidenceBinding
        binding.spool.close()


def _controller_terminal_receipt(
    contract: Day1BWorkerProtocolContract,
    controller_phase_audits: tuple[Day1BWorkerPhaseAudit, ...],
    observation: _ControllerCandidateObservation,
    spool: _ObjectReceiptSpool,
    *,
    expected_registry_descriptor: Day1BExpectedF1MRegistryDescriptor,
) -> Day1BWorkerCellReceipt:
    _validate_controller_phase_audits(contract, controller_phase_audits)
    failure_code = observation.terminal_failure_code
    assert failure_code is not None
    outcome = _OUTCOME_BY_FAILURE_CODE[failure_code]
    spool_sha256, spool_line_count, spool_byte_count = spool.seal(required_observed_f1m_phases=())
    return Day1BWorkerCellReceipt(
        input_binding=contract,
        f1m_controller_context_sha256=contract.f1m_controller_context_sha256,
        f1m_route_coverage_sha256=contract.f1m_route_coverage_sha256,
        f1m_charged_size_class_set_sha256=(contract.f1m_charged_size_class_set_sha256),
        candidate=Day1BWorkerCandidateReceipt(
            candidate_id=contract.candidate.candidate_id,
            candidate_role=contract.candidate.candidate_role,
            phases=(),
            elapsed_ns=observation.elapsed_ns,
            peak_resident_memory_bytes=observation.peak_resident_memory_bytes,
            peak_scratch_bytes=observation.peak_scratch_bytes,
            candidate_retry_count=0,
            worker_declared_state_reset_count=None,
            terminal_outcome=outcome,
            terminal_failure_code=failure_code,
            receipt_origin="controller-terminal-null-projection",
        ),
        controller_schedule_phase_audits=controller_phase_audits,
        worker_declared_phase_audits_match_controller_schedule_audits=False,
        runtime_state_continuity_verified=False,
        controller_expected_f1m_size_class_set_sha256=(contract.expected_f1m_size_class_set_sha256),
        controller_expected_f1m_size_class_count=contract.expected_f1m_size_class_count,
        controller_expected_f1m_phase_size_class_counts=(
            expected_registry_descriptor.phase_size_class_counts
        ),
        controller_expected_f1m_phase_query_counts=(
            expected_registry_descriptor.phase_query_counts
        ),
        controller_expected_f1m_phase_random_route_counts=(
            expected_registry_descriptor.phase_random_route_counts
        ),
        controller_expected_f1m_phase_dummy_route_counts=(
            expected_registry_descriptor.phase_dummy_route_counts
        ),
        controller_f1m_cardinality_derivation_root_sha256=(
            expected_registry_descriptor.cardinality_derivation_root_sha256
        ),
        controller_expected_serialized_equivalence_class_count=(
            contract.expected_serialized_equivalence_class_count
        ),
        worker_observed_f1m_size_class_count=spool.observed_f1m_size_class_count,
        worker_observed_f1m_materialized_binding_count=0,
        pre_dispatch_context_sha256=(expected_registry_descriptor.pre_dispatch_context_sha256),
        controller_registered_scratch_bytes_checkpoint_maximum=(
            expected_registry_descriptor.controller_registered_scratch_bytes_checkpoint_maximum
        ),
        controller_observed_registered_scratch_peak_bytes=(
            spool.controller_registered_scratch_peak_bytes
        ),
        anonymous_scratch_creation_isolation_verified=(
            expected_registry_descriptor.anonymous_scratch_creation_isolation_verified
        ),
        controller_f1m_window_batch_stream_sha256=(
            expected_registry_descriptor.controller_f1m_window_batch_stream_sha256
        ),
        weighted_query_range_coverage_verified=(
            expected_registry_descriptor.weighted_query_range_coverage_verified
        ),
        production_execution_admissible=False,
        object_receipt_spool_sha256=spool_sha256,
        object_receipt_line_count=spool_line_count,
        object_receipt_byte_count=spool_byte_count,
    )


def _consume_claimed_day1b_worker_frames(
    chunks: Iterable[bytes],
    *,
    contract: Day1BWorkerProtocolContract,
    invocation: _InvocationBinding,
) -> Day1BWorkerEvidenceCapability:
    """Decode one already-claimed invocation; the public wrapper retains ownership."""

    controller_candidate_observation = invocation.observation
    controller_phase_audits = invocation.controller_phase_audits
    spool = invocation.spool
    limit_failure_code = _controller_limit_failure_code(
        contract.resource_limits,
        controller_candidate_observation,
    )
    if limit_failure_code is not None and (
        controller_candidate_observation.terminal_failure_code != limit_failure_code
    ):
        spool.close()
        raise Day1BWorkerProtocolError(
            "controller resource-limit observation requires the matching terminal code"
        )
    resource_terminal_codes = {
        "resident-memory-limit-exceeded",
        "scratch-limit-exceeded",
        "wall-clock-limit-exceeded",
    }
    if (
        limit_failure_code is None
        and controller_candidate_observation.terminal_failure_code in resource_terminal_codes
    ):
        spool.close()
        raise Day1BWorkerProtocolError(
            "controller resource-specific terminal code is under its measured cap"
        )
    if controller_candidate_observation.terminal_failure_code is not None:
        if type(chunks) is not tuple or chunks:
            spool.close()
            raise Day1BWorkerProtocolError(
                "controller-terminal evidence must discard all worker transcript chunks"
            )
        try:
            receipt = _controller_terminal_receipt(
                contract,
                controller_phase_audits,
                controller_candidate_observation,
                spool,
                expected_registry_descriptor=invocation.expected_registry_descriptor,
            )
            return _mint_evidence_capability(receipt, spool)
        except BaseException:
            with suppress(BaseException):
                spool.close()
            raise
    try:
        iterator = iter(chunks)
    except TypeError as error:
        spool.close()
        raise TypeError("worker chunks must be iterable") from error
    builder = _ReceiptBuilder(
        contract,
        spool,
        controller_candidate_observation,
        invocation.expected_registry_descriptor,
    )
    length_prefix = bytearray()
    header_buffer = bytearray()
    header_length: int | None = None
    payload_remaining = 0
    payload_hasher: hashlib._Hash | None = None  # type: ignore[attr-defined]
    current_header: dict[str, object] | None = None
    expected_sequence = 0

    def accept_header(raw_header: bytes) -> None:
        nonlocal current_header, payload_remaining, payload_hasher, expected_sequence
        header = _decode_header(raw_header)
        if expected_sequence >= contract.resource_limits.worker_frame_count_maximum:
            raise Day1BWorkerProtocolError("worker frame count exceeds frozen cap")
        kind = _validate_frame_header(
            header,
            expected_sequence=expected_sequence,
            contract=contract,
        )
        expected_sequence += 1
        payload_remaining = int(header["payload_byte_count"])
        current_header = header
        if payload_remaining:
            if kind != "serialized-object":  # pragma: no cover - checked above
                raise Day1BWorkerProtocolError("only serialized objects may carry payloads")
            payload_hasher = hashlib.sha256()
        else:
            builder.accept(header, None)
            current_header = None

    try:
        for raw_chunk in iterator:
            if type(raw_chunk) is not bytes or not raw_chunk:
                raise Day1BWorkerProtocolError(
                    "worker transport chunks must be nonempty exact bytes"
                )
            position = 0
            while position < len(raw_chunk):
                if payload_remaining:
                    take = min(payload_remaining, len(raw_chunk) - position)
                    assert payload_hasher is not None and current_header is not None
                    payload_hasher.update(memoryview(raw_chunk)[position : position + take])
                    position += take
                    payload_remaining -= take
                    if payload_remaining == 0:
                        builder.accept(current_header, payload_hasher.hexdigest())
                        payload_hasher = None
                        current_header = None
                    continue
                if header_length is None:
                    take = min(4 - len(length_prefix), len(raw_chunk) - position)
                    length_prefix.extend(raw_chunk[position : position + take])
                    position += take
                    if len(length_prefix) < 4:
                        continue
                    header_length = int.from_bytes(length_prefix, "big")
                    length_prefix.clear()
                    if not 1 <= header_length <= DAY1B_WORKER_MAX_HEADER_BYTES:
                        raise Day1BWorkerProtocolError(
                            "worker frame header length is outside the fixed small bound"
                        )
                take = min(header_length - len(header_buffer), len(raw_chunk) - position)
                header_buffer.extend(raw_chunk[position : position + take])
                position += take
                if len(header_buffer) == header_length:
                    raw_header = bytes(header_buffer)
                    header_buffer.clear()
                    header_length = None
                    accept_header(raw_header)
        if (
            payload_remaining
            or current_header is not None
            or header_length is not None
            or length_prefix
        ):
            raise Day1BWorkerProtocolError("worker transcript is truncated")
        receipt = builder.finish(controller_phase_audits)
        return _mint_evidence_capability(receipt, spool)
    except BaseException:
        with suppress(BaseException):
            spool.close()
        raise


def consume_day1b_worker_frames(
    chunks: Iterable[bytes],
    *,
    contract: Day1BWorkerProtocolContract,
    invocation_capability: Day1BWorkerInvocationCapability,
) -> Day1BWorkerEvidenceCapability:
    """Claim launcher facts and retain spool ownership until evidence mint succeeds."""

    if type(contract) is not Day1BWorkerProtocolContract:
        raise TypeError("contract must be an exact Day1BWorkerProtocolContract")
    invocation = _claim_invocation(invocation_capability, contract)
    try:
        return _consume_claimed_day1b_worker_frames(
            chunks,
            contract=contract,
            invocation=invocation,
        )
    except BaseException:
        with suppress(BaseException):
            invocation.spool.close()
        raise


__all__ = (
    "DAY1B_WORKER_FRAME_SCHEMA",
    "DAY1B_WORKER_F1M_BINDING_SCHEMA",
    "DAY1B_WORKER_F1M_SIZE_CLASS_SCHEMA",
    "DAY1B_WORKER_EXPECTED_F1M_SIZE_CLASS_SET_SCHEMA",
    "DAY1B_WORKER_EXPECTED_F1M_OBJECT_SCHEMA",
    "DAY1B_WORKER_EXPECTED_F1M_REGISTRY_DESCRIPTOR_SCHEMA",
    "DAY1B_WORKER_EXECUTION_BASIS",
    "DAY1B_WORKER_F1M_WINDOW_BATCH_SCHEMA",
    "DAY1B_WORKER_INPUT_BINDING_SCHEMA",
    "DAY1B_WORKER_MAX_HEADER_BYTES",
    "DAY1B_WORKER_REQUIRED_F1M_SIZE_CLASS_CATEGORIES",
    "DAY1B_WORKER_RECEIPT_SCHEMA",
    "DAY1B_WORKER_WINDOW_AUDIT_SCHEMA",
    "DAY1B_WORKER_F1M_WINDOW_CARDINALITY_SCHEMA",
    "Day1BAnonymousScratchCapability",
    "Day1BClaimedWorkerEvidence",
    "Day1BControllerExpectedF1MObject",
    "Day1BExpectedF1MRegistryCapability",
    "Day1BExpectedF1MRegistryDescriptor",
    "Day1BF1MWindowBatch",
    "Day1BF1MBindingReceipt",
    "Day1BF1MSizeClass",
    "Day1BF1MWindowCardinality",
    "Day1BWorkerCandidateReceipt",
    "Day1BWorkerCandidateSpec",
    "Day1BWorkerCellReceipt",
    "Day1BWorkerEvidenceCapability",
    "Day1BWorkerInvocationCapability",
    "Day1BWorkerPhaseAudit",
    "Day1BWorkerPhaseReceipt",
    "Day1BWorkerPhaseRange",
    "Day1BWorkerProtocolContract",
    "Day1BWorkerProtocolError",
    "Day1BWorkerResourceLimits",
    "Day1BWorkerSerializedCategoryReceipt",
    "abandon_day1b_worker_evidence",
    "abandon_day1b_expected_f1m_registry",
    "abandon_day1b_worker_invocation",
    "canonical_day1b_expected_f1m_size_class_set_sha256",
    "canonical_day1b_expected_f1m_size_class_subroot_sha256",
    "canonical_day1b_f1m_cardinality_derivation_root_sha256",
    "canonical_day1b_f1m_query_id",
    "canonical_day1b_worker_window_audit_bytes",
    "claim_day1b_worker_evidence",
    "consume_day1b_worker_frames",
    "describe_day1b_expected_f1m_registry",
)
