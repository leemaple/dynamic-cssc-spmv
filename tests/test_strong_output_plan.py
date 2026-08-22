from __future__ import annotations

from dynamic_cssc.events import NetUpdate
from dynamic_cssc.output_plan import OutputPlan, OutputShare, analyze_output_plan
from dynamic_cssc.strong_packed_coo import (
    StrongEntry,
    advance_segmented_delta,
    initialize_segmented_delta,
    post_aggregation_output_shares,
)


def _state_with_three_segments_for_row_zero():
    state = initialize_segmented_delta(
        rows=4,
        cols=64,
        effective_slots=4,
        segment_width=2,
        matrix_value_bound=20,
        version_id="v0",
    )
    return advance_segmented_delta(
        state,
        delta_updates=(),
        overflow_entries=tuple(
            StrongEntry(0, global_col, global_col - 15) for global_col in range(16, 21)
        ),
        version_id="v1",
    ).state


def test_output_shares_map_only_active_post_reduction_leader_lanes() -> None:
    shares = post_aggregation_output_shares(_state_with_three_segments_for_row_zero())

    assert shares == (
        OutputShare(
            "strong-packed-coo-delta",
            "page-000000",
            ((0, 0), (2, 0)),
        ),
        OutputShare("strong-packed-coo-delta", "page-000001", ((0, 0),)),
    )
    assert all(
        physical_lane % 2 == 0 for share in shares for physical_lane, _ in share.slot_to_logical
    )


def test_allocated_leader_mapping_is_stable_when_a_segment_becomes_all_tombstone() -> None:
    state = _state_with_three_segments_for_row_zero()
    deleted = advance_segmented_delta(
        state,
        delta_updates=(
            NetUpdate(0, 16, 1, 0),
            NetUpdate(0, 17, 2, 0),
        ),
        overflow_entries=(),
        version_id="v2",
    ).state

    assert post_aggregation_output_shares(deleted) == (
        OutputShare(
            "strong-packed-coo-delta",
            "page-000000",
            ((0, 0), (2, 0)),
        ),
        OutputShare("strong-packed-coo-delta", "page-000001", ((0, 0),)),
    )


def test_f1m_multiplicity_counts_base_and_each_reduced_segment_once() -> None:
    delta_shares = post_aggregation_output_shares(_state_with_three_segments_for_row_zero())
    plan = OutputPlan(
        logical_output_size=4,
        slot_count=4,
        shares=(OutputShare("base", "rows", ((0, 0), (1, 1))), *delta_shares),
    )

    analysis = analyze_output_plan(plan)

    assert analysis.result_ciphertexts == 3
    assert analysis.masked_result_ciphertexts == 3
    assert analysis.client_reorder_elements == 5
    assert analysis.client_modular_additions == 3
    assert analysis.mask_random_elements == 3
    assert analysis.mask_mapped_elements == 4
