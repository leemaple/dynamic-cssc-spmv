from __future__ import annotations

from dynamic_cssc.publication_day1b_aggregate_bounds import (
    DAY1B_AGGREGATE_RECEIPT_CANONICAL_BYTES_MAXIMUM,
    DAY1B_F1M_SERIALIZED_CATEGORIES,
    SERIALIZED_PROTOCOL_OBJECT_CATEGORIES,
    publication_day1b_aggregate_static_bounds,
)
from dynamic_cssc.publication_day1b_worker_protocol import DAY1B_WORKER_MAX_HEADER_BYTES


def test_category_table_is_closed_and_already_contains_f1m() -> None:
    names = tuple(category for category, _transaction in SERIALIZED_PROTOCOL_OBJECT_CATEGORIES)

    assert len(names) == 9
    assert len(set(names)) == 9
    assert set(DAY1B_F1M_SERIALIZED_CATEGORIES) <= set(names)
    assert tuple(
        transaction for _category, transaction in SERIALIZED_PROTOCOL_OBJECT_CATEGORIES
    ).count("one-time") == 1


def test_role_aware_aggregate_receipt_and_ledger_bounds_are_exact() -> None:
    bounds = publication_day1b_aggregate_static_bounds()

    assert bounds.reference_candidate_count == 13
    assert bounds.ablation_candidate_count == 1
    assert bounds.candidate_cell_count_per_unit == 252
    assert bounds.schema_ledger_rows_per_reference_cell == 18
    assert bounds.schema_ledger_rows_per_ablation_cell == 9
    assert bounds.schema_ledger_rows_per_unit == 4_374
    assert bounds.aggregate_receipts_per_reference_cell == 17
    assert bounds.aggregate_receipts_per_ablation_cell == 9
    assert bounds.aggregate_receipts_per_unit == 4_140
    assert bounds.aggregate_receipts_per_unit < 17 * 252


def test_f1m_is_a_subset_and_uses_role_aware_structural_bounds() -> None:
    bounds = publication_day1b_aggregate_static_bounds()

    assert bounds.f1m_receipts_per_reference_cell == 4
    assert bounds.f1m_receipts_per_ablation_cell == 2
    assert bounds.f1m_receipts_per_unit == 972
    assert bounds.f1m_receipts_per_unit < 4 * 252
    assert bounds.f1m_receipts_per_unit < bounds.aggregate_receipts_per_unit


def test_frame_spool_payload_and_job_bounds_have_no_window_multiplier() -> None:
    bounds = publication_day1b_aggregate_static_bounds()

    assert bounds.worker_frames_per_reference_cell == 24
    assert bounds.worker_frames_per_ablation_cell == 16
    assert bounds.worker_frames_per_unit == 5_904
    assert bounds.aggregate_receipt_spool_bytes_per_reference_cell == 34_816
    assert bounds.aggregate_receipt_spool_bytes_per_ablation_cell == 18_432
    assert bounds.aggregate_receipt_spool_bytes_per_unit == 8_478_720
    assert bounds.raw_protocol_payload_bytes_per_candidate_cell == 0
    assert bounds.aggregate_receipts_per_job == 124_200
    assert bounds.f1m_receipts_per_job == 29_160
    assert bounds.worker_frames_per_job == 177_120
    assert bounds.aggregate_receipt_spool_bytes_per_job == 254_361_600
    assert DAY1B_AGGREGATE_RECEIPT_CANONICAL_BYTES_MAXIMUM == 2_048
    assert (
        DAY1B_AGGREGATE_RECEIPT_CANONICAL_BYTES_MAXIMUM
        <= DAY1B_WORKER_MAX_HEADER_BYTES
    )
