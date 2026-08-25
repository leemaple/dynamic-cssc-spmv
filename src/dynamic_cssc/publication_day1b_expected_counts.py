"""Open controller authority for Day 1B primitive and object multiplicities.

The worker may measure representative serialized size classes, but it may not
choose the logical operation or protocol-object multiplicities that those
representatives price.  This module projects the deterministic controller
replay into one small, canonical preimage that the worker input, receipt, and
serialization ledger can all open and verify.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

from dynamic_cssc.day2_calibration_authority import PRIMITIVE_NAMES
from dynamic_cssc.publication_day1b_accounting import PublicationDay1BAccounting
from dynamic_cssc.publication_day1b_aggregate_bounds import (
    SERIALIZED_PROTOCOL_OBJECT_CATEGORIES,
)

DAY1B_CONTROLLER_EXPECTED_COUNTS_SCHEMA = (
    "dynamic-cssc-publication-day1b-controller-expected-counts-v1"
)
DAY1B_CONTROLLER_EXPECTED_PHASE_COUNTS_SCHEMA = (
    "dynamic-cssc-publication-day1b-controller-expected-phase-counts-v1"
)

_PHASES = ("warmup", "tuning-prefix", "held-out")
_RETAINED_PHASE_SETS = (("tuning-prefix", "held-out"), ("held-out",))
_F1M_CATEGORIES = (
    "query-f1m-random-mask-ciphertexts",
    "query-f1m-encrypted-zero-dummy-ciphertexts",
)
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class Day1BControllerExpectedCountsError(ValueError):
    """Raised when controller-owned expected counts are not one exact preimage."""


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
        raise Day1BControllerExpectedCountsError(
            "controller expected counts are not canonical JSON"
        ) from error
    return (rendered + "\n").encode("ascii")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _require_sha256(value: object, field: str) -> str:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise Day1BControllerExpectedCountsError(
            f"{field} must be an exact lowercase SHA-256"
        )
    return value


def _count_tuple(
    value: object,
    field: str,
    *,
    expected_length: int,
) -> tuple[int, ...]:
    if type(value) is not tuple or not value or any(
        type(item) is not int or item < 0 for item in value
    ):
        raise Day1BControllerExpectedCountsError(
            f"{field} must be one nonempty tuple of strict nonnegative integers"
        )
    if len(value) != expected_length:
        raise Day1BControllerExpectedCountsError(
            f"{field} must contain exactly {expected_length} entries"
        )
    return value


@dataclass(frozen=True, slots=True)
class Day1BControllerExpectedPhaseCounts:
    """Exact primitive vectors and logical/worker object counts for one phase."""

    phase: str
    update_primitive_counts: tuple[int, ...]
    query_primitive_counts: tuple[int, ...]
    logical_protocol_object_counts: tuple[int, ...]
    worker_streamed_protocol_object_counts: tuple[int, ...]

    def __post_init__(self) -> None:
        if self.phase not in _PHASES:
            raise Day1BControllerExpectedCountsError(
                "controller expected-count phase is not frozen"
            )
        update = _count_tuple(
            self.update_primitive_counts,
            "controller expected update primitive counts",
            expected_length=len(PRIMITIVE_NAMES),
        )
        query = _count_tuple(
            self.query_primitive_counts,
            "controller expected query primitive counts",
            expected_length=len(PRIMITIVE_NAMES),
        )
        logical = _count_tuple(
            self.logical_protocol_object_counts,
            "controller expected logical protocol-object counts",
            expected_length=len(SERIALIZED_PROTOCOL_OBJECT_CATEGORIES),
        )
        worker = _count_tuple(
            self.worker_streamed_protocol_object_counts,
            "controller expected worker-streamed protocol-object counts",
            expected_length=len(SERIALIZED_PROTOCOL_OBJECT_CATEGORIES),
        )
        if len(update) != len(query) or len(logical) != len(worker):
            raise Day1BControllerExpectedCountsError(
                "controller expected-count vector dimensions disagree"
            )

    def to_document(self) -> dict[str, object]:
        return {
            "logical_protocol_object_counts": list(
                self.logical_protocol_object_counts
            ),
            "phase": self.phase,
            "query_primitive_counts": list(self.query_primitive_counts),
            "schema_version": DAY1B_CONTROLLER_EXPECTED_PHASE_COUNTS_SCHEMA,
            "update_primitive_counts": list(self.update_primitive_counts),
            "worker_streamed_protocol_object_counts": list(
                self.worker_streamed_protocol_object_counts
            ),
        }

    @classmethod
    def from_document(cls, value: object) -> Day1BControllerExpectedPhaseCounts:
        expected_keys = {
            "logical_protocol_object_counts",
            "phase",
            "query_primitive_counts",
            "schema_version",
            "update_primitive_counts",
            "worker_streamed_protocol_object_counts",
        }
        if type(value) is not dict or set(value) != expected_keys:
            raise Day1BControllerExpectedCountsError(
                "controller expected phase-count keys are not exact"
            )
        if value["schema_version"] != DAY1B_CONTROLLER_EXPECTED_PHASE_COUNTS_SCHEMA:
            raise Day1BControllerExpectedCountsError(
                "controller expected phase-count schema changed"
            )
        tuple_fields = (
            "update_primitive_counts",
            "query_primitive_counts",
            "logical_protocol_object_counts",
            "worker_streamed_protocol_object_counts",
        )
        if any(type(value[field]) is not list for field in tuple_fields):
            raise Day1BControllerExpectedCountsError(
                "controller expected phase-count vectors are not exact lists"
            )
        result = cls(
            phase=value["phase"],
            update_primitive_counts=tuple(value["update_primitive_counts"]),
            query_primitive_counts=tuple(value["query_primitive_counts"]),
            logical_protocol_object_counts=tuple(
                value["logical_protocol_object_counts"]
            ),
            worker_streamed_protocol_object_counts=tuple(
                value["worker_streamed_protocol_object_counts"]
            ),
        )
        if result.to_document() != value:
            raise Day1BControllerExpectedCountsError(
                "controller expected phase counts are not their exact typed projection"
            )
        return result


@dataclass(frozen=True, slots=True)
class Day1BControllerExpectedCounts:
    """Candidate-cell controller preimage bound into every worker invocation."""

    candidate_id: str
    candidate_policy_sha256: str
    accounting_sha256: str
    primitive_names: tuple[str, ...]
    serialized_categories: tuple[tuple[str, str], ...]
    phases: tuple[Day1BControllerExpectedPhaseCounts, ...]

    def __post_init__(self) -> None:
        if type(self.candidate_id) is not str or not self.candidate_id:
            raise Day1BControllerExpectedCountsError(
                "controller expected-count candidate identity is empty"
            )
        _require_sha256(
            self.candidate_policy_sha256,
            "controller expected-count candidate policy",
        )
        _require_sha256(self.accounting_sha256, "controller expected-count accounting")
        if (
            type(self.primitive_names) is not tuple
            or not self.primitive_names
            or any(type(name) is not str or not name for name in self.primitive_names)
            or len(self.primitive_names) != len(set(self.primitive_names))
        ):
            raise Day1BControllerExpectedCountsError(
                "controller expected-count primitive names are not exact"
            )
        if type(self.serialized_categories) is not tuple or not self.serialized_categories:
            raise Day1BControllerExpectedCountsError(
                "controller expected-count serialized categories are empty"
            )
        category_names: list[str] = []
        one_time_indices: list[int] = []
        for index, item in enumerate(self.serialized_categories):
            if (
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or not item[0]
                or type(item[1]) is not str
                or item[1] not in {"update", "query", "one-time"}
            ):
                raise Day1BControllerExpectedCountsError(
                    "controller expected-count serialized category is malformed"
                )
            category_names.append(item[0])
            if item[1] == "one-time":
                one_time_indices.append(index)
        if (
            len(category_names) != len(set(category_names))
            or len(one_time_indices) != 1
            or not set(_F1M_CATEGORIES) <= set(category_names)
        ):
            raise Day1BControllerExpectedCountsError(
                "controller expected-count category taxonomy is not closed"
            )
        if (
            type(self.phases) is not tuple
            or tuple(phase.phase for phase in self.phases) not in _RETAINED_PHASE_SETS
            or any(
                type(phase) is not Day1BControllerExpectedPhaseCounts
                for phase in self.phases
            )
        ):
            raise Day1BControllerExpectedCountsError(
                "controller expected counts must cover the exact retained phases"
            )
        f1m_indices = tuple(category_names.index(category) for category in _F1M_CATEGORIES)
        one_time_index = one_time_indices[0]
        one_time_pattern: list[int] = []
        for phase in self.phases:
            if (
                len(phase.update_primitive_counts) != len(self.primitive_names)
                or len(phase.query_primitive_counts) != len(self.primitive_names)
                or len(phase.logical_protocol_object_counts) != len(category_names)
                or len(phase.worker_streamed_protocol_object_counts)
                != len(category_names)
            ):
                raise Day1BControllerExpectedCountsError(
                    "controller expected-count matrix dimensions changed"
                )
            for category_index, (logical, worker) in enumerate(
                zip(
                    phase.logical_protocol_object_counts,
                    phase.worker_streamed_protocol_object_counts,
                    strict=True,
                )
            ):
                if category_index in f1m_indices:
                    if worker not in {0, logical}:
                        raise Day1BControllerExpectedCountsError(
                            "F1-M worker multiplicity must be zero or the full logical count"
                        )
                elif worker != logical:
                    raise Day1BControllerExpectedCountsError(
                        "non-F1-M worker multiplicity differs from controller logic"
                    )
            if (
                phase.logical_protocol_object_counts[one_time_index]
                != phase.worker_streamed_protocol_object_counts[one_time_index]
            ):
                raise Day1BControllerExpectedCountsError(
                    "one-time logical and worker multiplicities disagree"
                )
            one_time_pattern.append(
                phase.logical_protocol_object_counts[one_time_index]
            )
        if tuple(one_time_pattern) not in {
            tuple(0 for _phase in self.phases),
            tuple(int(index == 0) for index, _phase in enumerate(self.phases)),
        }:
            raise Day1BControllerExpectedCountsError(
                "one-time inventory must be absent or occur once in the first retained phase"
            )

    def to_document(self) -> dict[str, object]:
        return {
            "accounting_sha256": self.accounting_sha256,
            "candidate_id": self.candidate_id,
            "candidate_policy_sha256": self.candidate_policy_sha256,
            "phases": [phase.to_document() for phase in self.phases],
            "primitive_names": list(self.primitive_names),
            "schema_version": DAY1B_CONTROLLER_EXPECTED_COUNTS_SCHEMA,
            "serialized_categories": [list(item) for item in self.serialized_categories],
        }

    @classmethod
    def from_document(cls, value: object) -> Day1BControllerExpectedCounts:
        expected_keys = {
            "accounting_sha256",
            "candidate_id",
            "candidate_policy_sha256",
            "phases",
            "primitive_names",
            "schema_version",
            "serialized_categories",
        }
        if type(value) is not dict or set(value) != expected_keys:
            raise Day1BControllerExpectedCountsError(
                "controller expected-count document keys are not exact"
            )
        if value["schema_version"] != DAY1B_CONTROLLER_EXPECTED_COUNTS_SCHEMA:
            raise Day1BControllerExpectedCountsError(
                "controller expected-count document schema changed"
            )
        phases = value["phases"]
        primitive_names = value["primitive_names"]
        categories = value["serialized_categories"]
        if (
            type(phases) is not list
            or type(primitive_names) is not list
            or type(categories) is not list
            or any(type(item) is not list or len(item) != 2 for item in categories)
        ):
            raise Day1BControllerExpectedCountsError(
                "controller expected-count tuple projections are not exact lists"
            )
        result = cls(
            candidate_id=value["candidate_id"],
            candidate_policy_sha256=value["candidate_policy_sha256"],
            accounting_sha256=value["accounting_sha256"],
            primitive_names=tuple(primitive_names),
            serialized_categories=tuple(tuple(item) for item in categories),
            phases=tuple(
                Day1BControllerExpectedPhaseCounts.from_document(item)
                for item in phases
            ),
        )
        if result.to_document() != value:
            raise Day1BControllerExpectedCountsError(
                "controller expected counts are not their exact typed projection"
            )
        return result

    @property
    def expected_counts_sha256(self) -> str:
        return _digest(self.to_document())

    def phase_counts(self, phase: str) -> Day1BControllerExpectedPhaseCounts:
        for item in self.phases:
            if item.phase == phase:
                return item
        raise Day1BControllerExpectedCountsError(
            "requested phase is not retained by the expected-count preimage"
        )


def derive_day1b_controller_expected_counts(
    *,
    accounting: PublicationDay1BAccounting,
    retained_phases: tuple[str, ...],
    primitive_names: tuple[str, ...],
    serialized_categories: tuple[tuple[str, str], ...],
    phase_random_route_counts: tuple[int, int, int],
    phase_dummy_route_counts: tuple[int, int, int],
) -> Day1BControllerExpectedCounts:
    """Project one complete deterministic replay into its formal count authority."""

    if type(accounting) is not PublicationDay1BAccounting:
        raise TypeError("accounting must be exact PublicationDay1BAccounting")
    if retained_phases not in _RETAINED_PHASE_SETS:
        raise Day1BControllerExpectedCountsError("retained phase set is not frozen")
    if serialized_categories != SERIALIZED_PROTOCOL_OBJECT_CATEGORIES:
        raise Day1BControllerExpectedCountsError(
            "formal expected counts require the exact Day 1B category taxonomy"
        )
    for value, field in (
        (phase_random_route_counts, "random route counts"),
        (phase_dummy_route_counts, "dummy route counts"),
    ):
        if type(value) is not tuple or len(value) != len(_PHASES) or any(
            type(item) is not int or item < 0 for item in value
        ):
            raise Day1BControllerExpectedCountsError(
                f"controller expected {field} are not one exact three-phase tuple"
            )
    phase_by_name = {phase.phase: phase for phase in accounting.phases}
    if tuple(phase_by_name) != _PHASES:
        raise Day1BControllerExpectedCountsError(
            "controller accounting phase order changed"
        )
    for index, phase_name in enumerate(_PHASES):
        phase = phase_by_name[phase_name]
        if (
            phase.blinding_mask_ciphertexts != phase_random_route_counts[index]
            or phase.blinding_dummy_ciphertexts != phase_dummy_route_counts[index]
        ):
            raise Day1BControllerExpectedCountsError(
                "accounting F1-M multiplicities differ from opened controller routes"
            )

    category_index = {
        category: index
        for index, (category, _transaction) in enumerate(serialized_categories)
    }
    phases: list[Day1BControllerExpectedPhaseCounts] = []
    for retained_index, phase_name in enumerate(retained_phases):
        phase = phase_by_name[phase_name]
        logical = [0] * len(serialized_categories)
        logical[category_index["update-column-index-synchronization"]] = (
            phase.metadata_units
        )
        logical[category_index["update-publication-ciphertexts"]] = (
            phase.update_encryptions
        )
        logical[category_index["update-version-plan-metadata"]] = (
            phase.realized_version_publication_count
        )
        logical[category_index["query-query-ciphertexts"]] = phase.query_ciphertexts
        logical[category_index["query-result-ciphertexts"]] = (
            phase.result_ciphertexts
        )
        logical[category_index["query-f1m-random-mask-ciphertexts"]] = (
            phase.blinding_mask_ciphertexts
        )
        logical[category_index["query-f1m-encrypted-zero-dummy-ciphertexts"]] = (
            phase.blinding_dummy_ciphertexts
        )
        logical[category_index["query-version-plan-metadata"]] = (
            phase.realized_query_count
        )
        logical[category_index["one-time-evaluation-key-material"]] = int(
            retained_index == 0
        )
        worker = list(logical)
        for category in _F1M_CATEGORIES:
            worker[category_index[category]] = 0
        phases.append(
            Day1BControllerExpectedPhaseCounts(
                phase=phase_name,
                update_primitive_counts=phase.update_primitive_counts,
                query_primitive_counts=phase.query_primitive_counts,
                logical_protocol_object_counts=tuple(logical),
                worker_streamed_protocol_object_counts=tuple(worker),
            )
        )
    return Day1BControllerExpectedCounts(
        candidate_id=accounting.candidate_id,
        candidate_policy_sha256=accounting.candidate_policy_sha256,
        accounting_sha256=accounting.accounting_sha256,
        primitive_names=primitive_names,
        serialized_categories=serialized_categories,
        phases=tuple(phases),
    )


def require_formal_day1b_f1m_worker_zero(
    expected_counts: Day1BControllerExpectedCounts,
) -> None:
    """Reject any formal preimage that asks the worker to stream F1-M objects.

    The generic worker protocol retains a materialized-F1-M fixture mode for its
    isolated protocol tests.  Publication Day 1B uses the weighted formal mode:
    controller route coverage owns the logical multiplicity and every retained
    phase must keep both worker-streamed F1-M multiplicities at zero, including
    phases whose eventual outcome is failed or controller-terminal.
    """

    if type(expected_counts) is not Day1BControllerExpectedCounts:
        raise TypeError("formal F1-M validation requires exact controller expected counts")
    if expected_counts.serialized_categories != SERIALIZED_PROTOCOL_OBJECT_CATEGORIES:
        raise Day1BControllerExpectedCountsError(
            "formal F1-M validation requires the exact Day 1B category taxonomy"
        )
    category_names = tuple(
        category for category, _transaction in expected_counts.serialized_categories
    )
    f1m_indices = tuple(category_names.index(category) for category in _F1M_CATEGORIES)
    if any(
        phase.worker_streamed_protocol_object_counts[index] != 0
        for phase in expected_counts.phases
        for index in f1m_indices
    ):
        raise Day1BControllerExpectedCountsError(
            "formal F1-M worker multiplicity must remain zero"
        )


__all__ = (
    "DAY1B_CONTROLLER_EXPECTED_COUNTS_SCHEMA",
    "DAY1B_CONTROLLER_EXPECTED_PHASE_COUNTS_SCHEMA",
    "Day1BControllerExpectedCounts",
    "Day1BControllerExpectedCountsError",
    "Day1BControllerExpectedPhaseCounts",
    "derive_day1b_controller_expected_counts",
    "require_formal_day1b_f1m_worker_zero",
)
