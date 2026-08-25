"""Frozen role-aware bounds for aggregate Day 1B worker evidence.

All Publication Windows and typed query routes are streamed into hash state.
Only one charged receipt per retained phase/category, plus one candidate-cell
one-time category, may enter the receipt spool.  Consequently none of these
bounds contains a window, query, or route-count multiplier.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from dynamic_cssc.publication_statistics import (
    FIXED_CANDIDATE_IDS,
    REFERENCE_CANDIDATE_IDS,
)

DAY1B_AGGREGATE_RECEIPT_CANONICAL_BYTES_MAXIMUM: Final = 2_048
"""Maximum complete canonical JSONL receipt bytes, including its newline."""

DAY1B_CELLS_PER_UNIT: Final = 18
DAY1B_UNITS_PER_JOB: Final = 30
DAY1B_WORKER_FIXED_FRAMES_PER_CANDIDATE_CELL: Final = 7
"""cell-start, candidate-start, three phase-result, candidate-result, cell-end."""

SERIALIZED_PROTOCOL_OBJECT_CATEGORIES: Final = (
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

DAY1B_PHASE_SCOPED_SERIALIZED_CATEGORIES: Final = tuple(
    category
    for category, transaction in SERIALIZED_PROTOCOL_OBJECT_CATEGORIES
    if transaction != "one-time"
)
DAY1B_ONE_TIME_SERIALIZED_CATEGORIES: Final = tuple(
    category
    for category, transaction in SERIALIZED_PROTOCOL_OBJECT_CATEGORIES
    if transaction == "one-time"
)
DAY1B_F1M_SERIALIZED_CATEGORIES: Final = (
    "query-f1m-random-mask-ciphertexts",
    "query-f1m-encrypted-zero-dummy-ciphertexts",
)


@dataclass(frozen=True, slots=True)
class Day1BAggregateStaticBounds:
    """Closed candidate-cell, unit, and 30-unit job maxima."""

    serialized_category_count: int
    phase_scoped_category_count: int
    one_time_category_count: int
    reference_candidate_count: int
    ablation_candidate_count: int
    candidate_cell_count_per_unit: int
    schema_ledger_rows_per_reference_cell: int
    schema_ledger_rows_per_ablation_cell: int
    schema_ledger_rows_per_unit: int
    aggregate_receipts_per_reference_cell: int
    aggregate_receipts_per_ablation_cell: int
    aggregate_receipts_per_unit: int
    f1m_receipts_per_reference_cell: int
    f1m_receipts_per_ablation_cell: int
    f1m_receipts_per_unit: int
    worker_frames_per_reference_cell: int
    worker_frames_per_ablation_cell: int
    worker_frames_per_unit: int
    aggregate_receipt_spool_bytes_per_reference_cell: int
    aggregate_receipt_spool_bytes_per_ablation_cell: int
    aggregate_receipt_spool_bytes_per_unit: int
    raw_protocol_payload_bytes_per_candidate_cell: int
    aggregate_receipts_per_job: int
    f1m_receipts_per_job: int
    worker_frames_per_job: int
    aggregate_receipt_spool_bytes_per_job: int

    def __post_init__(self) -> None:
        if any(
            type(getattr(self, field)) is not int or getattr(self, field) < 0
            for field in self.__dataclass_fields__
        ):
            raise ValueError("Day1B aggregate static bounds must be strict nonnegative integers")
        if self.raw_protocol_payload_bytes_per_candidate_cell != 0:
            raise ValueError("aggregate Day1B evidence must not retain raw protocol payloads")

    def to_document(self) -> dict[str, int | str]:
        return {
            "schema_version": "dynamic-cssc-publication-day1b-aggregate-static-bounds-v1",
            **{
                field: getattr(self, field)
                for field in self.__dataclass_fields__
            },
        }


def publication_day1b_aggregate_static_bounds() -> Day1BAggregateStaticBounds:
    """Derive all maxima from the frozen category and candidate-role tables."""

    reference_count = len(REFERENCE_CANDIDATE_IDS)
    ablation_count = len(FIXED_CANDIDATE_IDS) - reference_count
    if reference_count != 13 or ablation_count != 1:
        raise RuntimeError("frozen Day1B candidate-role cardinality changed")
    phase_categories = len(DAY1B_PHASE_SCOPED_SERIALIZED_CATEGORIES)
    one_time_categories = len(DAY1B_ONE_TIME_SERIALIZED_CATEGORIES)
    if phase_categories != 8 or one_time_categories != 1:
        raise RuntimeError("frozen Day1B serialized category taxonomy changed")

    reference_retained_phases = 2
    ablation_retained_phases = 1
    reference_ledger_rows = (
        reference_retained_phases * len(SERIALIZED_PROTOCOL_OBJECT_CATEGORIES)
    )
    ablation_ledger_rows = (
        ablation_retained_phases * len(SERIALIZED_PROTOCOL_OBJECT_CATEGORIES)
    )
    reference_receipts = reference_retained_phases * phase_categories + one_time_categories
    ablation_receipts = ablation_retained_phases * phase_categories + one_time_categories
    reference_f1m = reference_retained_phases * len(DAY1B_F1M_SERIALIZED_CATEGORIES)
    ablation_f1m = ablation_retained_phases * len(DAY1B_F1M_SERIALIZED_CATEGORIES)
    reference_cells = DAY1B_CELLS_PER_UNIT * reference_count
    ablation_cells = DAY1B_CELLS_PER_UNIT * ablation_count
    candidate_cells = reference_cells + ablation_cells
    ledger_rows_per_unit = (
        reference_cells * reference_ledger_rows
        + ablation_cells * ablation_ledger_rows
    )
    receipts_per_unit = (
        reference_cells * reference_receipts
        + ablation_cells * ablation_receipts
    )
    f1m_per_unit = reference_cells * reference_f1m + ablation_cells * ablation_f1m
    reference_frames = DAY1B_WORKER_FIXED_FRAMES_PER_CANDIDATE_CELL + reference_receipts
    ablation_frames = DAY1B_WORKER_FIXED_FRAMES_PER_CANDIDATE_CELL + ablation_receipts
    frames_per_unit = reference_cells * reference_frames + ablation_cells * ablation_frames
    reference_spool = (
        reference_receipts * DAY1B_AGGREGATE_RECEIPT_CANONICAL_BYTES_MAXIMUM
    )
    ablation_spool = (
        ablation_receipts * DAY1B_AGGREGATE_RECEIPT_CANONICAL_BYTES_MAXIMUM
    )
    spool_per_unit = (
        reference_cells * reference_spool + ablation_cells * ablation_spool
    )
    return Day1BAggregateStaticBounds(
        serialized_category_count=len(SERIALIZED_PROTOCOL_OBJECT_CATEGORIES),
        phase_scoped_category_count=phase_categories,
        one_time_category_count=one_time_categories,
        reference_candidate_count=reference_count,
        ablation_candidate_count=ablation_count,
        candidate_cell_count_per_unit=candidate_cells,
        schema_ledger_rows_per_reference_cell=reference_ledger_rows,
        schema_ledger_rows_per_ablation_cell=ablation_ledger_rows,
        schema_ledger_rows_per_unit=ledger_rows_per_unit,
        aggregate_receipts_per_reference_cell=reference_receipts,
        aggregate_receipts_per_ablation_cell=ablation_receipts,
        aggregate_receipts_per_unit=receipts_per_unit,
        f1m_receipts_per_reference_cell=reference_f1m,
        f1m_receipts_per_ablation_cell=ablation_f1m,
        f1m_receipts_per_unit=f1m_per_unit,
        worker_frames_per_reference_cell=reference_frames,
        worker_frames_per_ablation_cell=ablation_frames,
        worker_frames_per_unit=frames_per_unit,
        aggregate_receipt_spool_bytes_per_reference_cell=reference_spool,
        aggregate_receipt_spool_bytes_per_ablation_cell=ablation_spool,
        aggregate_receipt_spool_bytes_per_unit=spool_per_unit,
        raw_protocol_payload_bytes_per_candidate_cell=0,
        aggregate_receipts_per_job=receipts_per_unit * DAY1B_UNITS_PER_JOB,
        f1m_receipts_per_job=f1m_per_unit * DAY1B_UNITS_PER_JOB,
        worker_frames_per_job=frames_per_unit * DAY1B_UNITS_PER_JOB,
        aggregate_receipt_spool_bytes_per_job=spool_per_unit * DAY1B_UNITS_PER_JOB,
    )


__all__ = (
    "DAY1B_AGGREGATE_RECEIPT_CANONICAL_BYTES_MAXIMUM",
    "DAY1B_CELLS_PER_UNIT",
    "DAY1B_F1M_SERIALIZED_CATEGORIES",
    "DAY1B_ONE_TIME_SERIALIZED_CATEGORIES",
    "DAY1B_PHASE_SCOPED_SERIALIZED_CATEGORIES",
    "DAY1B_UNITS_PER_JOB",
    "DAY1B_WORKER_FIXED_FRAMES_PER_CANDIDATE_CELL",
    "SERIALIZED_PROTOCOL_OBJECT_CATEGORIES",
    "Day1BAggregateStaticBounds",
    "publication_day1b_aggregate_static_bounds",
)
