"""Exact cross-window F1-M charging without route×window receipt materialization.

Day 1B advances every persistent layout and derives every typed query plan.  This
module hashes that complete controller stream, reconciles its exact query ranges,
and collapses only the communication charge into at most one anchored ciphertext
size class per retained phase and F1-M kind.  It never claims that repeated masks
or ciphertext payloads were materialized by the experiment.

Logical charges are exact Python integers and may exceed the IEEE-754 exact
integer range.  Evidence consumers must therefore retain integer JSON semantics.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from fractions import Fraction
from typing import Final

from dynamic_cssc.publication_day1b_accounting import (
    Day1BQueryWindowAccounting,
    PublicationDay1BAccounting,
)
from dynamic_cssc.publication_day1b_aggregate_bounds import (
    DAY1B_AGGREGATE_RECEIPT_CANONICAL_BYTES_MAXIMUM,
    DAY1B_CELLS_PER_UNIT,
    DAY1B_F1M_SERIALIZED_CATEGORIES,
)
from dynamic_cssc.publication_traces import PUBLICATION_SOURCE_PARTITION_COUNT

DAY1B_F1M_CHARGED_SIZE_CLASS_SCHEMA: Final = (
    "dynamic-cssc-publication-day1b-f1m-charged-size-class-v2"
)
DAY1B_F1M_CHARGED_SIZE_CLASS_SET_SCHEMA: Final = (
    "dynamic-cssc-publication-day1b-f1m-charged-size-class-set-v1"
)
DAY1B_F1M_CONTROLLER_SUMMARY_SCHEMA: Final = (
    "dynamic-cssc-publication-day1b-f1m-controller-summary-v4"
)
DAY1B_F1M_ROUTE_COVERAGE_SCHEMA: Final = "dynamic-cssc-publication-day1b-f1m-route-coverage-v2"
DAY1B_F1M_CONTROLLER_CONTEXT_SCHEMA: Final = (
    "dynamic-cssc-publication-day1b-f1m-controller-context-v2"
)
DAY1B_F1M_ACCOUNTING_BASIS: Final = "anchored-size-cross-window-charge-v1"
DAY1B_F1M_MAX_CHARGED_SIZE_CLASS_RECEIPTS_PER_CELL: Final = 4

_PHASES: Final = ("warmup", "tuning-prefix", "held-out")
_RETAINED_PHASE_SETS: Final = {
    ("tuning-prefix", "held-out"),
    ("held-out",),
}
_CATEGORY_BY_KIND: Final = dict(
    zip(
        ("random-zero-sum", "encrypted-zero-dummy"),
        DAY1B_F1M_SERIALIZED_CATEGORIES,
        strict=True,
    )
)
_KIND_BY_CATEGORY: Final = {value: key for key, value in _CATEGORY_BY_KIND.items()}
_SIZE_PROFILE_KEY_BY_KIND: Final = {
    "random-zero-sum": "f1m_random_zero_sum_ciphertext_bytes",
    "encrypted-zero-dummy": "f1m_encrypted_zero_dummy_ciphertext_bytes",
}
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")


class Day1BF1MAggregationError(ValueError):
    """Raised when weighted F1-M coverage or charging is not exact."""


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
        raise Day1BF1MAggregationError("F1-M value is not canonical JSON") from error
    return (rendered + "\n").encode("ascii")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _require_sha256(value: object, field: str) -> str:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise Day1BF1MAggregationError(f"{field} must be exact lowercase sha256")
    return value


def _require_git_sha(value: object, field: str) -> str:
    if type(value) is not str or _GIT_SHA.fullmatch(value) is None:
        raise Day1BF1MAggregationError(f"{field} must be an exact lowercase Git SHA")
    return value


def _positive(value: object, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise Day1BF1MAggregationError(f"{field} must be a positive strict integer")
    return value


def _nonnegative(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        raise Day1BF1MAggregationError(f"{field} must be a nonnegative strict integer")
    return value


def _nonempty(value: object, field: str) -> str:
    if type(value) is not str or not value:
        raise Day1BF1MAggregationError(f"{field} must be a nonempty string")
    return value


def _canonical_fraction_text(value: object, field: str) -> str:
    if type(value) is not str or not value:
        raise Day1BF1MAggregationError(f"{field} must be an exact positive rational")
    try:
        fraction = Fraction(value)
    except (ValueError, ZeroDivisionError) as error:
        raise Day1BF1MAggregationError(f"{field} must be an exact positive rational") from error
    if fraction <= 0:
        raise Day1BF1MAggregationError(f"{field} must be an exact positive rational")
    denominator = fraction.denominator
    terminating = denominator
    while terminating % 2 == 0:
        terminating //= 2
    while terminating % 5 == 0:
        terminating //= 5
    if terminating == 1:
        whole, remainder = divmod(fraction.numerator, denominator)
        digits: list[str] = []
        while remainder:
            remainder *= 10
            digit, remainder = divmod(remainder, denominator)
            digits.append(str(digit))
        expected = str(whole) if not digits else f"{whole}.{''.join(digits)}"
    else:
        expected = f"{fraction.numerator}/{fraction.denominator}"
    if value != expected:
        raise Day1BF1MAggregationError(f"{field} is not canonical")
    return value


@dataclass(frozen=True, slots=True)
class Day1BSerializedObjectSizeAuthority:
    """Read-only Day 2 serialization facts admitted before held-out input."""

    source_git_sha: str
    day2_experiment_source_git_sha: str
    day2_outer_archive_sha256: str
    serialized_object_size_profile_sha256: str
    ciphertext_bytes: int
    f1m_random_zero_sum_ciphertext_bytes: int
    f1m_encrypted_zero_dummy_ciphertext_bytes: int
    serialized_rotation_key_inventory_bytes: int
    serialized_eval_mult_key_bytes: int

    def __post_init__(self) -> None:
        _require_git_sha(self.source_git_sha, "size-authority source Git SHA")
        _require_git_sha(
            self.day2_experiment_source_git_sha,
            "size-authority Day 2 experiment source Git SHA",
        )
        _require_sha256(self.day2_outer_archive_sha256, "Day 2 outer archive SHA")
        _require_sha256(
            self.serialized_object_size_profile_sha256,
            "serialized-object size-profile SHA",
        )
        for field in (
            "ciphertext_bytes",
            "f1m_random_zero_sum_ciphertext_bytes",
            "f1m_encrypted_zero_dummy_ciphertext_bytes",
            "serialized_rotation_key_inventory_bytes",
            "serialized_eval_mult_key_bytes",
        ):
            _positive(getattr(self, field), field)

    def to_document(self) -> dict[str, object]:
        return {
            "ciphertext_bytes": self.ciphertext_bytes,
            "day2_experiment_source_git_sha": self.day2_experiment_source_git_sha,
            "day2_outer_archive_sha256": self.day2_outer_archive_sha256,
            "f1m_encrypted_zero_dummy_ciphertext_bytes": (
                self.f1m_encrypted_zero_dummy_ciphertext_bytes
            ),
            "f1m_random_zero_sum_ciphertext_bytes": (self.f1m_random_zero_sum_ciphertext_bytes),
            "serialized_eval_mult_key_bytes": self.serialized_eval_mult_key_bytes,
            "serialized_object_size_profile_sha256": (self.serialized_object_size_profile_sha256),
            "serialized_rotation_key_inventory_bytes": (
                self.serialized_rotation_key_inventory_bytes
            ),
            "source_git_sha": self.source_git_sha,
        }


@dataclass(frozen=True, slots=True)
class Day1BF1MPhaseBoundary:
    phase: str
    accepted_group_start: int
    accepted_group_end: int

    def __post_init__(self) -> None:
        if self.phase not in _PHASES:
            raise Day1BF1MAggregationError("F1-M context phase boundary is not frozen")
        _nonnegative(self.accepted_group_start, "phase accepted-group start")
        if (
            type(self.accepted_group_end) is not int
            or self.accepted_group_end <= self.accepted_group_start
        ):
            raise Day1BF1MAggregationError("F1-M context phase boundary is empty")

    def to_document(self) -> dict[str, int | str]:
        return {
            "accepted_group_end": self.accepted_group_end,
            "accepted_group_start": self.accepted_group_start,
            "phase": self.phase,
        }


@dataclass(frozen=True, slots=True)
class Day1BF1MCompletePhaseAudit:
    """One independently hashed full-window phase, including zero-query windows."""

    phase: str
    accepted_group_start: int
    accepted_group_end: int
    realized_window_count: int
    realized_set_count: int
    realized_query_count: int
    consumed_window_audit_stream_sha256: str

    def __post_init__(self) -> None:
        Day1BF1MPhaseBoundary(
            self.phase,
            self.accepted_group_start,
            self.accepted_group_end,
        )
        for field in (
            "realized_window_count",
            "realized_set_count",
            "realized_query_count",
        ):
            _nonnegative(getattr(self, field), f"complete phase audit {field}")
        if self.realized_window_count == 0:
            raise Day1BF1MAggregationError(
                "complete phase audit must contain at least one publication window"
            )
        _require_sha256(
            self.consumed_window_audit_stream_sha256,
            "complete phase window-audit stream SHA",
        )

    def to_document(self) -> dict[str, int | str]:
        return {
            "accepted_group_end": self.accepted_group_end,
            "accepted_group_start": self.accepted_group_start,
            "consumed_window_audit_stream_sha256": (self.consumed_window_audit_stream_sha256),
            "phase": self.phase,
            "realized_query_count": self.realized_query_count,
            "realized_set_count": self.realized_set_count,
            "realized_window_count": self.realized_window_count,
        }


@dataclass(frozen=True, slots=True)
class Day1BF1MCompleteScheduleAudit:
    """Closed three-phase audit derived by the all-window stream wrapper."""

    phase_audits: tuple[Day1BF1MCompletePhaseAudit, ...]

    def __post_init__(self) -> None:
        if (
            type(self.phase_audits) is not tuple
            or tuple(audit.phase for audit in self.phase_audits) != _PHASES
            or any(type(audit) is not Day1BF1MCompletePhaseAudit for audit in self.phase_audits)
        ):
            raise Day1BF1MAggregationError(
                "complete schedule audit must contain the exact three phases"
            )
        if self.phase_audits[0].accepted_group_start != 0 or any(
            before.accepted_group_end != after.accepted_group_start
            for before, after in zip(
                self.phase_audits,
                self.phase_audits[1:],
                strict=False,
            )
        ):
            raise Day1BF1MAggregationError(
                "complete schedule audit phase ranges are not contiguous from zero"
            )

    @property
    def complete_window_count(self) -> int:
        return sum(audit.realized_window_count for audit in self.phase_audits)

    @property
    def phase_window_counts(self) -> tuple[int, int, int]:
        return tuple(  # type: ignore[return-value]
            audit.realized_window_count for audit in self.phase_audits
        )

    @property
    def phase_query_counts(self) -> tuple[int, int, int]:
        return tuple(  # type: ignore[return-value]
            audit.realized_query_count for audit in self.phase_audits
        )

    @property
    def complete_phase_audit_root_sha256(self) -> str:
        return _sha256(
            {
                "phase_audits": [audit.to_document() for audit in self.phase_audits],
                "schema_version": ("dynamic-cssc-publication-day1b-complete-phase-audit-root-v1"),
            }
        )


@dataclass(frozen=True, slots=True)
class Day1BF1MControllerContext:
    """Closed lineage, candidate-cell, and complete-schedule binding."""

    publication_source_git_sha: str
    trace_source_git_sha: str
    publication_behavior_set_schema_version: str
    publication_behavior_inventory_sha256: str
    terminal_registration_sha256: str
    day1_registration_anchor_sha256: str
    trace_post_run_anchor_sha256: str
    acquisition_bundle_sha256: str
    trace_manifest_sha256: str
    candidate_catalog_sha256: str
    resource_policy_sha256: str
    worker_build_identity_sha256: str
    worker_runtime_identity_sha256: str
    dataset_id: str
    dataset_release: str
    semantics: str
    source_partition: int
    unit_identity_sha256: str
    cell_binding_sha256: str
    cell_ordinal: int
    freshness: str
    rho: str
    candidate_id: str
    candidate_role: str
    candidate_policy_sha256: str
    retained_phases: tuple[str, ...]
    phase_boundaries: tuple[Day1BF1MPhaseBoundary, ...]
    event_schedule_sha256: str
    query_vector_sha256: str
    accepted_group_count: int
    complete_window_count: int
    query_window_count: int
    zero_query_window_count: int
    total_query_count: int
    phase_window_counts: tuple[int, int, int]
    phase_query_counts: tuple[int, int, int]
    complete_window_stream_sha256: str
    complete_phase_audit_root_sha256: str
    accounting_sha256: str
    query_window_stream_sha256: str

    def __post_init__(self) -> None:
        _require_git_sha(
            self.publication_source_git_sha,
            "F1-M context publication source Git SHA",
        )
        _require_git_sha(
            self.trace_source_git_sha,
            "F1-M context trace source Git SHA",
        )
        _nonempty(
            self.publication_behavior_set_schema_version,
            "F1-M context Behavior Set schema",
        )
        for field in (
            "publication_behavior_inventory_sha256",
            "terminal_registration_sha256",
            "day1_registration_anchor_sha256",
            "trace_post_run_anchor_sha256",
            "acquisition_bundle_sha256",
            "trace_manifest_sha256",
            "candidate_catalog_sha256",
            "resource_policy_sha256",
            "worker_build_identity_sha256",
            "worker_runtime_identity_sha256",
            "unit_identity_sha256",
            "cell_binding_sha256",
            "candidate_policy_sha256",
            "event_schedule_sha256",
            "query_vector_sha256",
            "complete_window_stream_sha256",
            "complete_phase_audit_root_sha256",
            "accounting_sha256",
            "query_window_stream_sha256",
        ):
            _require_sha256(getattr(self, field), f"F1-M context {field}")
        for field in ("dataset_id", "dataset_release", "semantics", "candidate_id"):
            _nonempty(getattr(self, field), f"F1-M context {field}")
        if type(self.source_partition) is not int or self.source_partition not in range(
            PUBLICATION_SOURCE_PARTITION_COUNT
        ):
            raise Day1BF1MAggregationError(
                "F1-M context source partition is outside the frozen domain"
            )
        if type(self.cell_ordinal) is not int or self.cell_ordinal not in range(
            DAY1B_CELLS_PER_UNIT
        ):
            raise Day1BF1MAggregationError("F1-M context cell ordinal is outside the frozen unit")
        _canonical_fraction_text(self.freshness, "F1-M context freshness")
        _canonical_fraction_text(self.rho, "F1-M context rho")
        if self.candidate_role not in {"reference", "ablation"}:
            raise Day1BF1MAggregationError("F1-M context candidate role is not frozen")
        expected_retained = (
            ("tuning-prefix", "held-out") if self.candidate_role == "reference" else ("held-out",)
        )
        if self.retained_phases != expected_retained:
            raise Day1BF1MAggregationError(
                "F1-M context retained phases do not match the candidate role"
            )
        if (
            type(self.phase_boundaries) is not tuple
            or tuple(boundary.phase for boundary in self.phase_boundaries) != _PHASES
            or any(
                type(boundary) is not Day1BF1MPhaseBoundary for boundary in self.phase_boundaries
            )
        ):
            raise Day1BF1MAggregationError("F1-M context phase boundaries are not exact")
        if self.phase_boundaries[0].accepted_group_start != 0 or any(
            before.accepted_group_end != after.accepted_group_start
            for before, after in zip(
                self.phase_boundaries,
                self.phase_boundaries[1:],
                strict=False,
            )
        ):
            raise Day1BF1MAggregationError(
                "F1-M context phase boundaries are not contiguous from zero"
            )
        self._validate_counts()

    def _validate_counts(self) -> None:
        _positive(self.accepted_group_count, "F1-M context accepted-group count")
        for field in (
            "complete_window_count",
            "query_window_count",
            "zero_query_window_count",
            "total_query_count",
        ):
            _nonnegative(getattr(self, field), f"F1-M context {field}")
        for field in ("phase_window_counts", "phase_query_counts"):
            value = getattr(self, field)
            if (
                type(value) is not tuple
                or len(value) != len(_PHASES)
                or any(type(item) is not int or item < 0 for item in value)
            ):
                raise Day1BF1MAggregationError(f"F1-M context {field} is not exact")
        if self.phase_boundaries[-1].accepted_group_end != self.accepted_group_count:
            raise Day1BF1MAggregationError(
                "F1-M context phase boundaries do not cover all accepted groups"
            )
        if sum(self.phase_window_counts) != self.complete_window_count:
            raise Day1BF1MAggregationError("F1-M context phase window counts do not reconcile")
        if sum(self.phase_query_counts) != self.total_query_count:
            raise Day1BF1MAggregationError("F1-M context phase query counts do not reconcile")
        if (
            self.query_window_count + self.zero_query_window_count != self.complete_window_count
            or self.query_window_count > self.total_query_count
        ):
            raise Day1BF1MAggregationError(
                "F1-M context complete/query/zero-window counts do not reconcile"
            )

    @property
    def context_sha256(self) -> str:
        return _sha256(self.to_document())

    def to_document(self) -> dict[str, object]:
        return {
            "accepted_group_count": self.accepted_group_count,
            "accounting_sha256": self.accounting_sha256,
            "acquisition_bundle_sha256": self.acquisition_bundle_sha256,
            "candidate_id": self.candidate_id,
            "candidate_catalog_sha256": self.candidate_catalog_sha256,
            "candidate_policy_sha256": self.candidate_policy_sha256,
            "candidate_role": self.candidate_role,
            "cell_binding_sha256": self.cell_binding_sha256,
            "cell_ordinal": self.cell_ordinal,
            "complete_phase_audit_root_sha256": (self.complete_phase_audit_root_sha256),
            "complete_window_count": self.complete_window_count,
            "complete_window_stream_sha256": self.complete_window_stream_sha256,
            "dataset_id": self.dataset_id,
            "dataset_release": self.dataset_release,
            "day1_registration_anchor_sha256": (self.day1_registration_anchor_sha256),
            "event_schedule_sha256": self.event_schedule_sha256,
            "first_query_ordinal": 0,
            "first_window_ordinal": 0,
            "freshness": self.freshness,
            "last_query_ordinal_exclusive": self.total_query_count,
            "last_window_ordinal": self.complete_window_count - 1,
            "phase_boundaries": [boundary.to_document() for boundary in self.phase_boundaries],
            "phase_query_counts": dict(zip(_PHASES, self.phase_query_counts, strict=True)),
            "phase_window_counts": dict(zip(_PHASES, self.phase_window_counts, strict=True)),
            "publication_behavior_inventory_sha256": (self.publication_behavior_inventory_sha256),
            "publication_behavior_set_schema_version": (
                self.publication_behavior_set_schema_version
            ),
            "publication_source_git_sha": self.publication_source_git_sha,
            "query_vector_sha256": self.query_vector_sha256,
            "query_window_count": self.query_window_count,
            "query_window_stream_sha256": self.query_window_stream_sha256,
            "retained_phases": list(self.retained_phases),
            "resource_policy_sha256": self.resource_policy_sha256,
            "rho": self.rho,
            "schema_version": DAY1B_F1M_CONTROLLER_CONTEXT_SCHEMA,
            "semantics": self.semantics,
            "source_partition": self.source_partition,
            "terminal_registration_sha256": self.terminal_registration_sha256,
            "total_query_count": self.total_query_count,
            "trace_post_run_anchor_sha256": self.trace_post_run_anchor_sha256,
            "trace_manifest_sha256": self.trace_manifest_sha256,
            "trace_source_git_sha": self.trace_source_git_sha,
            "unit_identity_sha256": self.unit_identity_sha256,
            "worker_build_identity_sha256": self.worker_build_identity_sha256,
            "worker_runtime_identity_sha256": self.worker_runtime_identity_sha256,
            "zero_query_window_count": self.zero_query_window_count,
        }

    @classmethod
    def from_document(cls, value: object) -> Day1BF1MControllerContext:
        """Open one exact retained controller-context preimage."""

        keys = {
            "accepted_group_count",
            "accounting_sha256",
            "acquisition_bundle_sha256",
            "candidate_id",
            "candidate_catalog_sha256",
            "candidate_policy_sha256",
            "candidate_role",
            "cell_binding_sha256",
            "cell_ordinal",
            "complete_phase_audit_root_sha256",
            "complete_window_count",
            "complete_window_stream_sha256",
            "dataset_id",
            "dataset_release",
            "day1_registration_anchor_sha256",
            "event_schedule_sha256",
            "first_query_ordinal",
            "first_window_ordinal",
            "freshness",
            "last_query_ordinal_exclusive",
            "last_window_ordinal",
            "phase_boundaries",
            "phase_query_counts",
            "phase_window_counts",
            "publication_behavior_inventory_sha256",
            "publication_behavior_set_schema_version",
            "publication_source_git_sha",
            "query_vector_sha256",
            "query_window_count",
            "query_window_stream_sha256",
            "retained_phases",
            "resource_policy_sha256",
            "rho",
            "schema_version",
            "semantics",
            "source_partition",
            "terminal_registration_sha256",
            "total_query_count",
            "trace_post_run_anchor_sha256",
            "trace_manifest_sha256",
            "trace_source_git_sha",
            "unit_identity_sha256",
            "worker_build_identity_sha256",
            "worker_runtime_identity_sha256",
            "zero_query_window_count",
        }
        if type(value) is not dict or set(value) != keys:
            raise Day1BF1MAggregationError("F1-M controller-context document keys are not exact")
        if value["schema_version"] != DAY1B_F1M_CONTROLLER_CONTEXT_SCHEMA:
            raise Day1BF1MAggregationError("F1-M controller-context schema changed")
        raw_boundaries = value["phase_boundaries"]
        if type(raw_boundaries) is not list or len(raw_boundaries) != len(_PHASES):
            raise Day1BF1MAggregationError("F1-M controller-context boundaries are not exact")
        phase_boundaries: list[Day1BF1MPhaseBoundary] = []
        for raw_boundary in raw_boundaries:
            if type(raw_boundary) is not dict or set(raw_boundary) != {
                "accepted_group_end",
                "accepted_group_start",
                "phase",
            }:
                raise Day1BF1MAggregationError(
                    "F1-M controller-context boundary keys are not exact"
                )
            phase_boundaries.append(Day1BF1MPhaseBoundary(**raw_boundary))
        phase_query_counts = value["phase_query_counts"]
        phase_window_counts = value["phase_window_counts"]
        if (
            type(phase_query_counts) is not dict
            or set(phase_query_counts) != set(_PHASES)
            or type(phase_window_counts) is not dict
            or set(phase_window_counts) != set(_PHASES)
        ):
            raise Day1BF1MAggregationError("F1-M controller-context phase counts are not exact")
        retained_phases = value["retained_phases"]
        if type(retained_phases) is not list:
            raise Day1BF1MAggregationError("F1-M controller-context retained phases are not exact")
        context = cls(
            publication_source_git_sha=value["publication_source_git_sha"],
            trace_source_git_sha=value["trace_source_git_sha"],
            publication_behavior_set_schema_version=(
                value["publication_behavior_set_schema_version"]
            ),
            publication_behavior_inventory_sha256=(
                value["publication_behavior_inventory_sha256"]
            ),
            terminal_registration_sha256=value["terminal_registration_sha256"],
            day1_registration_anchor_sha256=value["day1_registration_anchor_sha256"],
            trace_post_run_anchor_sha256=value["trace_post_run_anchor_sha256"],
            acquisition_bundle_sha256=value["acquisition_bundle_sha256"],
            trace_manifest_sha256=value["trace_manifest_sha256"],
            candidate_catalog_sha256=value["candidate_catalog_sha256"],
            resource_policy_sha256=value["resource_policy_sha256"],
            worker_build_identity_sha256=value["worker_build_identity_sha256"],
            worker_runtime_identity_sha256=value["worker_runtime_identity_sha256"],
            dataset_id=value["dataset_id"],
            dataset_release=value["dataset_release"],
            semantics=value["semantics"],
            source_partition=value["source_partition"],
            unit_identity_sha256=value["unit_identity_sha256"],
            cell_binding_sha256=value["cell_binding_sha256"],
            cell_ordinal=value["cell_ordinal"],
            freshness=value["freshness"],
            rho=value["rho"],
            candidate_id=value["candidate_id"],
            candidate_role=value["candidate_role"],
            candidate_policy_sha256=value["candidate_policy_sha256"],
            retained_phases=tuple(retained_phases),
            phase_boundaries=tuple(phase_boundaries),
            event_schedule_sha256=value["event_schedule_sha256"],
            query_vector_sha256=value["query_vector_sha256"],
            accepted_group_count=value["accepted_group_count"],
            complete_window_count=value["complete_window_count"],
            query_window_count=value["query_window_count"],
            zero_query_window_count=value["zero_query_window_count"],
            total_query_count=value["total_query_count"],
            phase_window_counts=tuple(phase_window_counts[phase] for phase in _PHASES),
            phase_query_counts=tuple(phase_query_counts[phase] for phase in _PHASES),
            complete_window_stream_sha256=value["complete_window_stream_sha256"],
            complete_phase_audit_root_sha256=value["complete_phase_audit_root_sha256"],
            accounting_sha256=value["accounting_sha256"],
            query_window_stream_sha256=value["query_window_stream_sha256"],
        )
        if context.to_document() != value:
            raise Day1BF1MAggregationError(
                "F1-M controller-context document is not its exact typed projection"
            )
        return context


@dataclass(frozen=True, slots=True)
class Day1BF1MRouteCoverage:
    """Small retained preimage around one opaque per-window route-stream hash."""

    controller_context_sha256: str
    day2_outer_archive_sha256: str
    element_count: int
    element_stream_sha256: str
    phase_dummy_route_counts: tuple[int, int, int]
    phase_query_counts: tuple[int, int, int]
    phase_query_window_counts: tuple[int, int, int]
    phase_random_route_counts: tuple[int, int, int]
    serialized_object_size_profile_sha256: str

    def __post_init__(self) -> None:
        for field in (
            "controller_context_sha256",
            "day2_outer_archive_sha256",
            "element_stream_sha256",
            "serialized_object_size_profile_sha256",
        ):
            _require_sha256(getattr(self, field), f"F1-M route coverage {field}")
        _nonnegative(self.element_count, "F1-M route coverage element count")
        for field in (
            "phase_dummy_route_counts",
            "phase_query_counts",
            "phase_query_window_counts",
            "phase_random_route_counts",
        ):
            counts = getattr(self, field)
            if (
                type(counts) is not tuple
                or len(counts) != len(_PHASES)
                or any(type(item) is not int or item < 0 for item in counts)
            ):
                raise Day1BF1MAggregationError(
                    f"F1-M route coverage {field} is not an exact phase tuple"
                )
        if sum(self.phase_query_window_counts) != self.element_count or any(
            windows > queries
            for windows, queries in zip(
                self.phase_query_window_counts,
                self.phase_query_counts,
                strict=True,
            )
        ):
            raise Day1BF1MAggregationError(
                "F1-M route coverage query-window counts do not reconcile"
            )
        if any(
            queries == 0 and (random_count != 0 or dummy_count != 0)
            for queries, random_count, dummy_count in zip(
                self.phase_query_counts,
                self.phase_random_route_counts,
                self.phase_dummy_route_counts,
                strict=True,
            )
        ):
            raise Day1BF1MAggregationError(
                "F1-M route coverage charges a phase with no queries"
            )

    @property
    def route_coverage_sha256(self) -> str:
        return _sha256(self.to_document())

    def to_document(self) -> dict[str, object]:
        return {
            "controller_context_sha256": self.controller_context_sha256,
            "day2_outer_archive_sha256": self.day2_outer_archive_sha256,
            "element_count": self.element_count,
            "element_stream_sha256": self.element_stream_sha256,
            "phase_dummy_route_counts": dict(
                zip(_PHASES, self.phase_dummy_route_counts, strict=True)
            ),
            "phase_query_counts": dict(zip(_PHASES, self.phase_query_counts, strict=True)),
            "phase_query_window_counts": dict(
                zip(_PHASES, self.phase_query_window_counts, strict=True)
            ),
            "phase_random_route_counts": dict(
                zip(_PHASES, self.phase_random_route_counts, strict=True)
            ),
            "schema_version": DAY1B_F1M_ROUTE_COVERAGE_SCHEMA,
            "serialized_object_size_profile_sha256": (
                self.serialized_object_size_profile_sha256
            ),
        }

    @classmethod
    def from_document(cls, value: object) -> Day1BF1MRouteCoverage:
        keys = {
            "controller_context_sha256",
            "day2_outer_archive_sha256",
            "element_count",
            "element_stream_sha256",
            "phase_dummy_route_counts",
            "phase_query_counts",
            "phase_query_window_counts",
            "phase_random_route_counts",
            "schema_version",
            "serialized_object_size_profile_sha256",
        }
        if type(value) is not dict or set(value) != keys:
            raise Day1BF1MAggregationError("F1-M route-coverage document keys are not exact")
        if value["schema_version"] != DAY1B_F1M_ROUTE_COVERAGE_SCHEMA:
            raise Day1BF1MAggregationError("F1-M route-coverage schema changed")
        count_fields = (
            "phase_dummy_route_counts",
            "phase_query_counts",
            "phase_query_window_counts",
            "phase_random_route_counts",
        )
        for field in count_fields:
            counts = value[field]
            if type(counts) is not dict or set(counts) != set(_PHASES):
                raise Day1BF1MAggregationError(
                    f"F1-M route-coverage {field} keys are not exact"
                )
        coverage = cls(
            controller_context_sha256=value["controller_context_sha256"],
            day2_outer_archive_sha256=value["day2_outer_archive_sha256"],
            element_count=value["element_count"],
            element_stream_sha256=value["element_stream_sha256"],
            phase_dummy_route_counts=tuple(
                value["phase_dummy_route_counts"][phase] for phase in _PHASES
            ),
            phase_query_counts=tuple(value["phase_query_counts"][phase] for phase in _PHASES),
            phase_query_window_counts=tuple(
                value["phase_query_window_counts"][phase] for phase in _PHASES
            ),
            phase_random_route_counts=tuple(
                value["phase_random_route_counts"][phase] for phase in _PHASES
            ),
            serialized_object_size_profile_sha256=(
                value["serialized_object_size_profile_sha256"]
            ),
        )
        if coverage.to_document() != value:
            raise Day1BF1MAggregationError(
                "F1-M route-coverage document is not its exact typed projection"
            )
        return coverage


@dataclass(frozen=True, slots=True)
class Day1BF1MChargedSizeClass:
    """One cross-window logical charge backed by an anchored Day 2 byte size."""

    phase: str
    category: str
    f1m_kind: str
    multiplicity: int
    ciphertext_bytes: int
    serialized_size_profile_key: str
    serialized_object_size_profile_sha256: str
    day2_outer_archive_sha256: str

    def __post_init__(self) -> None:
        if self.phase not in {"tuning-prefix", "held-out"}:
            raise Day1BF1MAggregationError("charged F1-M phase is not retained")
        if _KIND_BY_CATEGORY.get(self.category) != self.f1m_kind:
            raise Day1BF1MAggregationError("charged F1-M category/kind pair is not frozen")
        if self.serialized_size_profile_key != _SIZE_PROFILE_KEY_BY_KIND[self.f1m_kind]:
            raise Day1BF1MAggregationError(
                "charged F1-M serialized-size profile key is not category-specific"
            )
        _positive(self.multiplicity, "charged F1-M multiplicity")
        _positive(self.ciphertext_bytes, "charged F1-M ciphertext bytes")
        _require_sha256(
            self.serialized_object_size_profile_sha256,
            "charged F1-M size-profile SHA",
        )
        _require_sha256(self.day2_outer_archive_sha256, "charged F1-M Day 2 archive SHA")
        if (
            len(_canonical_bytes(self.to_document()))
            > DAY1B_AGGREGATE_RECEIPT_CANONICAL_BYTES_MAXIMUM
        ):
            raise Day1BF1MAggregationError(
                "charged F1-M canonical JSONL exceeds the frozen 2 KiB bound"
            )

    @property
    def charged_byte_count(self) -> int:
        return self.ciphertext_bytes * self.multiplicity

    def to_document(self) -> dict[str, object]:
        return {
            "accounting_basis": DAY1B_F1M_ACCOUNTING_BASIS,
            "category": self.category,
            "charged_byte_count": self.charged_byte_count,
            "ciphertext_bytes": self.ciphertext_bytes,
            "day2_outer_archive_sha256": self.day2_outer_archive_sha256,
            "f1m_kind": self.f1m_kind,
            "materialized_cryptographic_object_count": 0,
            "multiplicity": self.multiplicity,
            "phase": self.phase,
            "schema_version": DAY1B_F1M_CHARGED_SIZE_CLASS_SCHEMA,
            "serialized_size_profile_key": self.serialized_size_profile_key,
            "serialized_object_size_profile_sha256": (self.serialized_object_size_profile_sha256),
        }

    @classmethod
    def from_document(cls, value: object) -> Day1BF1MChargedSizeClass:
        keys = {
            "accounting_basis",
            "category",
            "charged_byte_count",
            "ciphertext_bytes",
            "day2_outer_archive_sha256",
            "f1m_kind",
            "materialized_cryptographic_object_count",
            "multiplicity",
            "phase",
            "schema_version",
            "serialized_size_profile_key",
            "serialized_object_size_profile_sha256",
        }
        if type(value) is not dict or set(value) != keys:
            raise Day1BF1MAggregationError("charged F1-M size-class document keys are not exact")
        if (
            value["schema_version"] != DAY1B_F1M_CHARGED_SIZE_CLASS_SCHEMA
            or value["accounting_basis"] != DAY1B_F1M_ACCOUNTING_BASIS
            or value["materialized_cryptographic_object_count"] != 0
        ):
            raise Day1BF1MAggregationError("charged F1-M size-class document semantics changed")
        item = cls(
            phase=value["phase"],
            category=value["category"],
            f1m_kind=value["f1m_kind"],
            multiplicity=value["multiplicity"],
            ciphertext_bytes=value["ciphertext_bytes"],
            serialized_size_profile_key=value["serialized_size_profile_key"],
            serialized_object_size_profile_sha256=(value["serialized_object_size_profile_sha256"]),
            day2_outer_archive_sha256=value["day2_outer_archive_sha256"],
        )
        if item.charged_byte_count != value["charged_byte_count"]:
            raise Day1BF1MAggregationError("charged F1-M size-class byte arithmetic changed")
        if item.to_document() != value:
            raise Day1BF1MAggregationError(
                "charged F1-M size-class document is not its exact typed projection"
            )
        return item


def canonical_day1b_f1m_charged_size_class_set_sha256(
    classes: tuple[Day1BF1MChargedSizeClass, ...],
) -> str:
    """Hash one canonical ordered set of typed retained F1-M charge classes."""

    if type(classes) is not tuple or any(
        type(item) is not Day1BF1MChargedSizeClass for item in classes
    ):
        raise Day1BF1MAggregationError("charged F1-M size-class set must be one exact typed tuple")
    return _sha256(
        {
            "classes": [item.to_document() for item in classes],
            "schema_version": DAY1B_F1M_CHARGED_SIZE_CLASS_SET_SCHEMA,
        }
    )


def derive_day1b_f1m_charged_size_classes(
    *,
    retained_phases: tuple[str, ...],
    phase_random_route_counts: tuple[int, int, int],
    phase_dummy_route_counts: tuple[int, int, int],
    size_authority: Day1BSerializedObjectSizeAuthority,
) -> tuple[Day1BF1MChargedSizeClass, ...]:
    category_sizes = {
        "random-zero-sum": size_authority.f1m_random_zero_sum_ciphertext_bytes,
        "encrypted-zero-dummy": (size_authority.f1m_encrypted_zero_dummy_ciphertext_bytes),
    }
    charged: list[Day1BF1MChargedSizeClass] = []
    for phase in retained_phases:
        phase_index = _PHASES.index(phase)
        for kind, counts in (
            ("random-zero-sum", phase_random_route_counts),
            ("encrypted-zero-dummy", phase_dummy_route_counts),
        ):
            multiplicity = counts[phase_index]
            if multiplicity == 0:
                continue
            charged.append(
                Day1BF1MChargedSizeClass(
                    phase=phase,
                    category=_CATEGORY_BY_KIND[kind],
                    f1m_kind=kind,
                    multiplicity=multiplicity,
                    ciphertext_bytes=category_sizes[kind],
                    serialized_size_profile_key=_SIZE_PROFILE_KEY_BY_KIND[kind],
                    serialized_object_size_profile_sha256=(
                        size_authority.serialized_object_size_profile_sha256
                    ),
                    day2_outer_archive_sha256=(size_authority.day2_outer_archive_sha256),
                )
            )
    return tuple(charged)


@dataclass(frozen=True, slots=True)
class Day1BF1MControllerSummary:
    """Closed controller proof and exact cross-window F1-M charges.

    The serialized-payload limit is retained as resource-policy provenance for
    the worker stream; it is not a ceiling on multiplicity-weighted logical charge.
    """

    context: Day1BF1MControllerContext
    size_authority: Day1BSerializedObjectSizeAuthority
    retained_phases: tuple[str, ...]
    query_window_stream_sha256: str
    route_coverage: Day1BF1MRouteCoverage
    query_window_count: int
    phase_query_window_counts: tuple[int, int, int]
    phase_query_counts: tuple[int, int, int]
    phase_random_route_counts: tuple[int, int, int]
    phase_dummy_route_counts: tuple[int, int, int]
    charged_size_classes: tuple[Day1BF1MChargedSizeClass, ...]
    serialized_object_bytes_maximum: int
    serialized_payload_bytes_per_cell_maximum: int

    def __post_init__(self) -> None:
        if type(self.context) is not Day1BF1MControllerContext:
            raise Day1BF1MAggregationError("F1-M controller context type is not exact")
        if type(self.size_authority) is not Day1BSerializedObjectSizeAuthority:
            raise Day1BF1MAggregationError("F1-M size authority type is not exact")
        if self.retained_phases not in _RETAINED_PHASE_SETS:
            raise Day1BF1MAggregationError("F1-M retained phase set is not frozen")
        if (
            self.context.retained_phases != self.retained_phases
            or self.context.publication_source_git_sha != self.size_authority.source_git_sha
        ):
            raise Day1BF1MAggregationError(
                "F1-M context does not bind the retained phases and size authority"
            )
        _require_sha256(self.query_window_stream_sha256, "query-window stream SHA")
        if type(self.route_coverage) is not Day1BF1MRouteCoverage:
            raise Day1BF1MAggregationError("F1-M route coverage type is not exact")
        _positive(
            self.serialized_object_bytes_maximum,
            "F1-M summary serialized-object byte maximum",
        )
        _positive(
            self.serialized_payload_bytes_per_cell_maximum,
            "F1-M summary serialized-payload byte maximum",
        )
        if type(self.query_window_count) is not int or self.query_window_count < 0:
            raise Day1BF1MAggregationError("F1-M query-window count is not nonnegative")
        for field in (
            "phase_query_window_counts",
            "phase_query_counts",
            "phase_random_route_counts",
            "phase_dummy_route_counts",
        ):
            value = getattr(self, field)
            if (
                type(value) is not tuple
                or len(value) != len(_PHASES)
                or any(type(item) is not int or item < 0 for item in value)
            ):
                raise Day1BF1MAggregationError(f"{field} is not an exact phase tuple")
        if sum(self.phase_query_window_counts) != self.query_window_count:
            raise Day1BF1MAggregationError("phase query-window counts do not reconcile")
        if (
            self.context.query_window_count != self.query_window_count
            or self.context.phase_query_counts != self.phase_query_counts
            or self.route_coverage.controller_context_sha256 != self.context.context_sha256
            or self.route_coverage.day2_outer_archive_sha256
            != self.size_authority.day2_outer_archive_sha256
            or self.route_coverage.serialized_object_size_profile_sha256
            != self.size_authority.serialized_object_size_profile_sha256
            or self.route_coverage.element_count != self.query_window_count
            or self.route_coverage.phase_query_window_counts
            != self.phase_query_window_counts
            or self.route_coverage.phase_query_counts != self.phase_query_counts
            or self.route_coverage.phase_random_route_counts
            != self.phase_random_route_counts
            or self.route_coverage.phase_dummy_route_counts != self.phase_dummy_route_counts
            or any(
                query_windows > all_windows
                for query_windows, all_windows in zip(
                    self.phase_query_window_counts,
                    self.context.phase_window_counts,
                    strict=True,
                )
            )
        ):
            raise Day1BF1MAggregationError(
                "F1-M query stream does not reconcile with the complete schedule context"
            )
        if (
            type(self.charged_size_classes) is not tuple
            or len(self.charged_size_classes) > DAY1B_F1M_MAX_CHARGED_SIZE_CLASS_RECEIPTS_PER_CELL
            or any(type(item) is not Day1BF1MChargedSizeClass for item in self.charged_size_classes)
        ):
            raise Day1BF1MAggregationError("charged F1-M size-class bound is not exact")
        expected_classes = derive_day1b_f1m_charged_size_classes(
            retained_phases=self.retained_phases,
            phase_random_route_counts=self.phase_random_route_counts,
            phase_dummy_route_counts=self.phase_dummy_route_counts,
            size_authority=self.size_authority,
        )
        if self.charged_size_classes != expected_classes:
            raise Day1BF1MAggregationError(
                "charged F1-M classes do not exactly derive from routes and Day 2 authority"
            )

    @property
    def route_coverage_sha256(self) -> str:
        return self.route_coverage.route_coverage_sha256

    @property
    def charged_size_class_set_sha256(self) -> str:
        return canonical_day1b_f1m_charged_size_class_set_sha256(self.charged_size_classes)

    @property
    def logical_charged_byte_count(self) -> int:
        return sum(item.charged_byte_count for item in self.charged_size_classes)

    def to_document(self) -> dict[str, object]:
        return {
            "accounting_basis": DAY1B_F1M_ACCOUNTING_BASIS,
            "charged_size_class_count": len(self.charged_size_classes),
            "charged_size_class_count_static_maximum": (
                DAY1B_F1M_MAX_CHARGED_SIZE_CLASS_RECEIPTS_PER_CELL
            ),
            "charged_size_class_set_sha256": self.charged_size_class_set_sha256,
            "charged_size_classes": [item.to_document() for item in self.charged_size_classes],
            "controller_context": self.context.to_document(),
            "controller_context_sha256": self.context.context_sha256,
            "logical_charged_byte_count": self.logical_charged_byte_count,
            "phase_dummy_route_counts": dict(
                zip(_PHASES, self.phase_dummy_route_counts, strict=True)
            ),
            "phase_query_counts": dict(zip(_PHASES, self.phase_query_counts, strict=True)),
            "phase_query_window_counts": dict(
                zip(_PHASES, self.phase_query_window_counts, strict=True)
            ),
            "phase_random_route_counts": dict(
                zip(_PHASES, self.phase_random_route_counts, strict=True)
            ),
            "query_window_count": self.query_window_count,
            "query_window_stream_sha256": self.query_window_stream_sha256,
            "retained_phases": list(self.retained_phases),
            "route_coverage": self.route_coverage.to_document(),
            "route_coverage_sha256": self.route_coverage_sha256,
            "schema_version": DAY1B_F1M_CONTROLLER_SUMMARY_SCHEMA,
            "serialized_object_bytes_maximum": self.serialized_object_bytes_maximum,
            "serialized_payload_bytes_per_cell_maximum": (
                self.serialized_payload_bytes_per_cell_maximum
            ),
            "size_authority": self.size_authority.to_document(),
        }


class Day1BF1MController:
    """Stream query windows once and finish one closed weighted F1-M summary."""

    __slots__ = (
        "_accepted_group_count",
        "_dummy_counts",
        "_expected_query_ordinal",
        "_f1m_policy",
        "_finished",
        "_phase_query_counts",
        "_phase_query_window_counts",
        "_previous_accepted_group_end",
        "_previous_order",
        "_query_stream_hasher",
        "_query_window_count",
        "_random_counts",
        "_retained_phases",
        "_route_stream_hasher",
        "_serialized_object_bytes_maximum",
        "_serialized_payload_bytes_per_cell_maximum",
        "_size_authority",
    )

    def __init__(
        self,
        *,
        accepted_group_count: int,
        retained_phases: tuple[str, ...],
        f1m_policy: str,
        size_authority: Day1BSerializedObjectSizeAuthority,
        serialized_object_bytes_maximum: int,
        serialized_payload_bytes_per_cell_maximum: int,
    ) -> None:
        self._accepted_group_count = _positive(
            accepted_group_count,
            "F1-M accepted-group count",
        )
        if retained_phases not in _RETAINED_PHASE_SETS:
            raise Day1BF1MAggregationError("F1-M retained phase set is not frozen")
        if f1m_policy not in {"overlap-only", "uniform-random-or-zero"}:
            raise Day1BF1MAggregationError("F1-M policy is not frozen")
        if type(size_authority) is not Day1BSerializedObjectSizeAuthority:
            raise TypeError("size_authority must be exact Day1BSerializedObjectSizeAuthority")
        self._serialized_object_bytes_maximum = _positive(
            serialized_object_bytes_maximum,
            "F1-M serialized-object byte maximum",
        )
        self._serialized_payload_bytes_per_cell_maximum = _positive(
            serialized_payload_bytes_per_cell_maximum,
            "F1-M serialized-payload byte maximum",
        )
        if (
            max(
                size_authority.ciphertext_bytes,
                size_authority.f1m_random_zero_sum_ciphertext_bytes,
                size_authority.f1m_encrypted_zero_dummy_ciphertext_bytes,
            )
            > self._serialized_object_bytes_maximum
        ):
            raise Day1BF1MAggregationError(
                "anchored F1-M ciphertext size exceeds the frozen object-byte cap"
            )
        self._retained_phases = retained_phases
        self._f1m_policy = f1m_policy
        self._size_authority = size_authority
        self._query_stream_hasher = hashlib.sha256()
        self._route_stream_hasher = hashlib.sha256()
        self._query_window_count = 0
        self._phase_query_window_counts = [0, 0, 0]
        self._phase_query_counts = [0, 0, 0]
        self._random_counts = [0, 0, 0]
        self._dummy_counts = [0, 0, 0]
        self._expected_query_ordinal = 0
        self._previous_order: tuple[int, int] | None = None
        self._previous_accepted_group_end = 0
        self._finished = False

    def accept_query_window(self, window: Day1BQueryWindowAccounting) -> None:
        if self._finished:
            raise Day1BF1MAggregationError("F1-M controller is already finished")
        if type(window) is not Day1BQueryWindowAccounting:
            raise TypeError("query-window stream contains a non-exact value")
        phase_index = _PHASES.index(window.phase)
        order = phase_index, window.window_index
        if self._previous_order is not None and order <= self._previous_order:
            raise Day1BF1MAggregationError("query windows are not in canonical phase/order")
        if (
            window.accepted_group_end > self._accepted_group_count
            or window.accepted_group_start < self._previous_accepted_group_end
        ):
            raise Day1BF1MAggregationError("query-window accepted-group ranges overlap or escape")
        if window.first_global_query_ordinal != self._expected_query_ordinal:
            raise Day1BF1MAggregationError("query-window ranges are not contiguous")
        plan = window.query_plan
        for field in (
            "cloud_program_digest",
            "output_plan_digest",
            "private_plan_digest",
            "execution_binding_digest",
        ):
            _require_sha256(getattr(plan, field), f"query plan {field}")
        if type(plan.version_id) is not str or not plan.version_id:
            raise Day1BF1MAggregationError("query plan version identity is empty")
        if (
            type(plan.f1m_routes) is not tuple
            or type(plan.returned_share_count) is not int
            or plan.returned_share_count < len(plan.f1m_routes)
        ):
            raise Day1BF1MAggregationError("query plan F1-M route cardinality is not exact")
        if (
            self._f1m_policy == "uniform-random-or-zero"
            and len(plan.f1m_routes) != plan.returned_share_count
        ):
            raise Day1BF1MAggregationError("uniform F1-M must classify every returned share")
        random_per_query = 0
        dummy_per_query = 0
        route_documents: list[dict[str, str | int]] = []
        result_ids: set[str] = set()
        result_ordinals: set[int] = set()
        route_identities: set[tuple[str, str]] = set()
        for expected_f1m_ordinal, route in enumerate(plan.f1m_routes):
            document = route.to_document()
            if set(document) != {
                "category",
                "component_id",
                "f1m_kind",
                "f1m_route_ordinal",
                "output_block_id",
                "result_id",
                "result_ordinal",
            }:
                raise Day1BF1MAggregationError("query plan F1-M route document changed")
            for field in ("component_id", "output_block_id", "result_id"):
                if type(document[field]) is not str or not document[field]:
                    raise Day1BF1MAggregationError(f"query plan F1-M {field} identity is empty")
            if document["f1m_route_ordinal"] != expected_f1m_ordinal:
                raise Day1BF1MAggregationError("query plan F1-M route ordinals are not contiguous")
            result_ordinal = document["result_ordinal"]
            if (
                type(result_ordinal) is not int
                or result_ordinal < 0
                or result_ordinal >= plan.returned_share_count
            ):
                raise Day1BF1MAggregationError(
                    "query plan F1-M result ordinal escapes the returned shares"
                )
            result_id = str(document["result_id"])
            route_identity = str(document["component_id"]), str(document["output_block_id"])
            if (
                result_id in result_ids
                or result_ordinal in result_ordinals
                or route_identity in route_identities
            ):
                raise Day1BF1MAggregationError("query plan F1-M route identities are not unique")
            result_ids.add(result_id)
            result_ordinals.add(result_ordinal)
            route_identities.add(route_identity)
            if document["f1m_kind"] == "random-zero-sum":
                if document["category"] != _CATEGORY_BY_KIND["random-zero-sum"]:
                    raise Day1BF1MAggregationError("random-zero-sum route category changed")
                random_per_query += 1
            elif document["f1m_kind"] == "encrypted-zero-dummy":
                if document["category"] != _CATEGORY_BY_KIND["encrypted-zero-dummy"]:
                    raise Day1BF1MAggregationError("encrypted-zero-dummy route category changed")
                dummy_per_query += 1
            else:
                raise Day1BF1MAggregationError("query plan F1-M route kind is not frozen")
            route_documents.append(
                {
                    **document,
                    "serialized_size_profile_key": _SIZE_PROFILE_KEY_BY_KIND[
                        str(document["f1m_kind"])
                    ],
                }
            )
        if self._f1m_policy == "overlap-only" and dummy_per_query:
            raise Day1BF1MAggregationError("overlap-only F1-M cannot charge dummy routes")

        document = window.to_document()
        raw = _canonical_bytes(document)
        self._query_stream_hasher.update(raw)
        self._route_stream_hasher.update(
            _canonical_bytes(
                {
                    "accepted_group_end": window.accepted_group_end,
                    "accepted_group_start": window.accepted_group_start,
                    "cloud_program_digest": plan.cloud_program_digest,
                    "execution_binding_digest": plan.execution_binding_digest,
                    "first_global_query_ordinal": window.first_global_query_ordinal,
                    "last_global_query_ordinal_exclusive": (
                        window.first_global_query_ordinal + window.query_count
                    ),
                    "f1m_policy": self._f1m_policy,
                    "f1m_routes": route_documents,
                    "f1m_route_count": len(route_documents),
                    "output_plan_digest": plan.output_plan_digest,
                    "phase": window.phase,
                    "private_plan_digest": plan.private_plan_digest,
                    "query_count": window.query_count,
                    "returned_share_count": plan.returned_share_count,
                    "version_id": plan.version_id,
                    "window_index": window.window_index,
                }
            )
        )
        self._query_window_count += 1
        self._phase_query_window_counts[phase_index] += 1
        self._phase_query_counts[phase_index] += window.query_count
        self._random_counts[phase_index] += random_per_query * window.query_count
        self._dummy_counts[phase_index] += dummy_per_query * window.query_count
        self._expected_query_ordinal += window.query_count
        self._previous_order = order
        self._previous_accepted_group_end = window.accepted_group_end

    def finish(
        self,
        *,
        context: Day1BF1MControllerContext,
        accounting: PublicationDay1BAccounting,
        complete_schedule_audit: Day1BF1MCompleteScheduleAudit,
    ) -> Day1BF1MControllerSummary:
        if self._finished:
            raise Day1BF1MAggregationError("F1-M controller is already finished")
        self._finished = True
        if type(context) is not Day1BF1MControllerContext:
            raise TypeError("context must be exact Day1BF1MControllerContext")
        if type(accounting) is not PublicationDay1BAccounting:
            raise TypeError("accounting must be exact PublicationDay1BAccounting")
        if type(complete_schedule_audit) is not Day1BF1MCompleteScheduleAudit:
            raise TypeError("complete_schedule_audit must be exact Day1BF1MCompleteScheduleAudit")
        if (
            context.accepted_group_count != self._accepted_group_count
            or context.retained_phases != self._retained_phases
            or context.publication_source_git_sha != self._size_authority.source_git_sha
        ):
            raise Day1BF1MAggregationError(
                "F1-M controller context changed accepted groups, retained phases, or source"
            )
        accounting_phase_ranges = tuple(
            (phase.phase, phase.accepted_group_start, phase.accepted_group_end)
            for phase in accounting.phases
        )
        audit_phase_ranges = tuple(
            (audit.phase, audit.accepted_group_start, audit.accepted_group_end)
            for audit in complete_schedule_audit.phase_audits
        )
        context_phase_ranges = tuple(
            (
                boundary.phase,
                boundary.accepted_group_start,
                boundary.accepted_group_end,
            )
            for boundary in context.phase_boundaries
        )
        accounting_phase_window_counts = tuple(
            phase.realized_window_count for phase in accounting.phases
        )
        accounting_phase_query_counts = tuple(
            phase.realized_query_count for phase in accounting.phases
        )
        accounting_phase_query_window_counts = tuple(
            phase.query_window_count for phase in accounting.phases
        )
        audit_phase_set_counts = tuple(
            audit.realized_set_count for audit in complete_schedule_audit.phase_audits
        )
        accounting_phase_set_counts = tuple(phase.realized_set_count for phase in accounting.phases)
        expected_zero_query_windows = (
            accounting.realized_window_count - accounting.realized_query_window_count
        )
        if (
            accounting.candidate_id != context.candidate_id
            or accounting.candidate_policy_sha256 != context.candidate_policy_sha256
            or accounting_phase_ranges != audit_phase_ranges
            or accounting_phase_ranges != context_phase_ranges
            or audit_phase_set_counts != accounting_phase_set_counts
            or complete_schedule_audit.phase_window_counts != accounting_phase_window_counts
            or complete_schedule_audit.phase_query_counts != accounting_phase_query_counts
            or complete_schedule_audit.complete_window_count != accounting.realized_window_count
            or context.complete_window_count != accounting.realized_window_count
            or context.query_window_count != accounting.realized_query_window_count
            or context.zero_query_window_count != expected_zero_query_windows
            or context.total_query_count != accounting.realized_query_count
            or context.phase_window_counts != accounting_phase_window_counts
            or context.phase_query_counts != accounting_phase_query_counts
            or context.complete_window_stream_sha256 != accounting.window_stream_sha256
            or context.complete_phase_audit_root_sha256
            != complete_schedule_audit.complete_phase_audit_root_sha256
            or context.accounting_sha256 != accounting.accounting_sha256
            or context.query_window_stream_sha256 != accounting.query_window_stream_sha256
            or tuple(self._phase_query_window_counts) != accounting_phase_query_window_counts
        ):
            raise Day1BF1MAggregationError(
                "F1-M context, accounting, and complete-window audit do not reconcile"
            )
        query_window_stream_sha256 = _sha256(
            {
                "element_count": self._query_window_count,
                "element_stream_sha256": self._query_stream_hasher.hexdigest(),
                "schema_version": "dynamic-cssc-publication-day1b-query-window-stream-v1",
            }
        )
        if query_window_stream_sha256 != context.query_window_stream_sha256:
            raise Day1BF1MAggregationError(
                "F1-M controller did not consume the exact accounting query-window stream"
            )
        if tuple(self._phase_query_counts) != context.phase_query_counts:
            raise Day1BF1MAggregationError(
                "F1-M controller phase query totals differ from accounting"
            )
        route_coverage = Day1BF1MRouteCoverage(
            controller_context_sha256=context.context_sha256,
            day2_outer_archive_sha256=self._size_authority.day2_outer_archive_sha256,
            element_count=self._query_window_count,
            element_stream_sha256=self._route_stream_hasher.hexdigest(),
            phase_dummy_route_counts=tuple(self._dummy_counts),  # type: ignore[arg-type]
            phase_query_counts=tuple(self._phase_query_counts),  # type: ignore[arg-type]
            phase_query_window_counts=tuple(
                self._phase_query_window_counts
            ),  # type: ignore[arg-type]
            phase_random_route_counts=tuple(self._random_counts),  # type: ignore[arg-type]
            serialized_object_size_profile_sha256=(
                self._size_authority.serialized_object_size_profile_sha256
            ),
        )
        charged = derive_day1b_f1m_charged_size_classes(
            retained_phases=self._retained_phases,
            phase_random_route_counts=tuple(self._random_counts),  # type: ignore[arg-type]
            phase_dummy_route_counts=tuple(self._dummy_counts),  # type: ignore[arg-type]
            size_authority=self._size_authority,
        )
        summary = Day1BF1MControllerSummary(
            context=context,
            size_authority=self._size_authority,
            retained_phases=self._retained_phases,
            query_window_stream_sha256=query_window_stream_sha256,
            route_coverage=route_coverage,
            query_window_count=self._query_window_count,
            phase_query_window_counts=tuple(self._phase_query_window_counts),  # type: ignore[arg-type]
            phase_query_counts=tuple(self._phase_query_counts),  # type: ignore[arg-type]
            phase_random_route_counts=tuple(self._random_counts),  # type: ignore[arg-type]
            phase_dummy_route_counts=tuple(self._dummy_counts),  # type: ignore[arg-type]
            charged_size_classes=charged,
            serialized_object_bytes_maximum=(self._serialized_object_bytes_maximum),
            serialized_payload_bytes_per_cell_maximum=(
                self._serialized_payload_bytes_per_cell_maximum
            ),
        )
        # Logical charge prices the exact scheduled multiplicity; it does not
        # allocate or retain those bytes.  The worker protocol independently
        # enforces this physical serialized-payload cap on its streamed objects.
        return summary


__all__ = (
    "DAY1B_F1M_ACCOUNTING_BASIS",
    "DAY1B_F1M_CHARGED_SIZE_CLASS_SCHEMA",
    "DAY1B_F1M_CHARGED_SIZE_CLASS_SET_SCHEMA",
    "DAY1B_F1M_CONTROLLER_CONTEXT_SCHEMA",
    "DAY1B_F1M_CONTROLLER_SUMMARY_SCHEMA",
    "DAY1B_F1M_MAX_CHARGED_SIZE_CLASS_RECEIPTS_PER_CELL",
    "Day1BF1MAggregationError",
    "Day1BF1MChargedSizeClass",
    "Day1BF1MCompletePhaseAudit",
    "Day1BF1MCompleteScheduleAudit",
    "Day1BF1MController",
    "Day1BF1MControllerContext",
    "Day1BF1MControllerSummary",
    "Day1BF1MPhaseBoundary",
    "Day1BF1MRouteCoverage",
    "Day1BSerializedObjectSizeAuthority",
    "canonical_day1b_f1m_charged_size_class_set_sha256",
    "derive_day1b_f1m_charged_size_classes",
)
