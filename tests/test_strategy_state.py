from __future__ import annotations

import copy
from dataclasses import replace

import pytest

import dynamic_cssc.strategy_state as strategy_state_module
from dynamic_cssc.events import NetUpdate, PublicationWindow
from dynamic_cssc.output_plan import analyze_output_plan
from dynamic_cssc.strategy_state import (
    STRATEGIES,
    TransitionFacts,
    advance_publication,
    assert_strategy_invariants,
    decode_state,
    initialize_strategy,
)


def _window(*updates: NetUpdate, index: int = 0, queries: int = 1) -> PublicationWindow:
    return PublicationWindow(
        index=index,
        start_time=float(index),
        end_time=float(index),
        updates=tuple(updates),
        query_count=queries,
        reason="query",
    )


@pytest.mark.parametrize("strategy", STRATEGIES)
def test_initialize_each_strategy_as_an_exact_versioned_state(strategy: str) -> None:
    logical = {(0, 0): 2, (0, 3): -1, (1, 1): 4, (2, 2): 1}

    state = initialize_strategy(
        strategy,
        logical,
        rows=3,
        cols=5,
        effective_slots=8,
        partition_rows=3,
        matrix_value_bound=7,
        max_row_nnz=4,
        reserved_slack_beta=0.5,
        periodic_repack_windows=2,
        packed_coo_segment_capacity=4,
    )

    assert state.version_ordinal == 0
    assert state.version_id == "v00000000"
    assert decode_state(state) == logical
    assert state.base.version_id == state.version_id
    assert state.delta is None
    assert state.repack_count == 0
    assert state.windows_since_repack == 0
    assert_strategy_invariants(state)


@pytest.mark.parametrize(
    ("update", "message"),
    (
        (NetUpdate(0, 0, 99, 3), "before"),
        (NetUpdate(True, 0, 2, 3), "strict integer"),
        (NetUpdate(3, 0, 0, 1), "outside"),
        (NetUpdate(0, 5, 0, 1), "outside"),
        (NetUpdate(0, 0, 2, True), "strict integer"),
        (NetUpdate(0, 0, 2, 8), "value bound"),
    ),
)
def test_invalid_window_is_rejected_without_mutating_state(
    update: NetUpdate, message: str
) -> None:
    state = initialize_strategy(
        "Mini-CSSC-Delta",
        {(0, 0): 2},
        rows=3,
        cols=5,
        effective_slots=8,
        partition_rows=3,
        matrix_value_bound=7,
        max_row_nnz=2,
    )
    snapshot = copy.deepcopy(state)

    with pytest.raises(ValueError, match=message):
        advance_publication(state, _window(update))

    assert state == snapshot
    assert decode_state(state) == {(0, 0): 2}


def test_window_row_bound_is_checked_after_all_updates_atomically() -> None:
    state = initialize_strategy(
        "Packed-COO-Client-Lane-Delta",
        {(0, 0): 1},
        rows=2,
        cols=4,
        effective_slots=4,
        partition_rows=2,
        matrix_value_bound=7,
        max_row_nnz=2,
        packed_coo_segment_capacity=2,
    )
    snapshot = copy.deepcopy(state)

    with pytest.raises(ValueError, match="row nonzero bound"):
        advance_publication(
            state,
            _window(NetUpdate(0, 1, 0, 1), NetUpdate(0, 2, 0, 1)),
        )

    assert state == snapshot


def test_duplicate_coordinate_in_one_window_is_rejected() -> None:
    state = initialize_strategy(
        "PaddingReuse-CSSC",
        {(0, 0): 1},
        rows=2,
        cols=4,
        effective_slots=4,
        partition_rows=2,
    )

    with pytest.raises(ValueError, match="unique coordinates"):
        advance_publication(
            state,
            _window(NetUpdate(0, 0, 1, 2), NetUpdate(0, 0, 1, 3)),
        )


def test_query_only_window_preserves_version_and_returns_real_row_map() -> None:
    state = initialize_strategy(
        "PaddingReuse-CSSC",
        {(0, 0): 1, (1, 0): 1, (1, 1): 2, (1, 2): 3, (2, 4): 4},
        rows=3,
        cols=5,
        effective_slots=8,
        partition_rows=3,
    )

    transition = advance_publication(state, _window(index=7, queries=3))

    assert transition.state is state
    assert transition.facts.updates == 0
    assert transition.facts.query_count == 3
    assert transition.output_plan.shares[0].slot_to_logical == (
        (0, 1),
        (1, 0),
        (2, 2),
    )


def test_padding_tombstone_retains_ci_then_is_consumed_once() -> None:
    state = initialize_strategy(
        "PaddingReuse-CSSC",
        {(0, 0): 1, (0, 1): 2, (0, 2): 3, (1, 0): 4, (1, 1): 5},
        rows=2,
        cols=6,
        effective_slots=8,
        partition_rows=2,
        max_row_nnz=6,
    )

    deleted = advance_publication(state, _window(NetUpdate(0, 0, 1, 0)))
    tombstone = next(
        lane for lane in deleted.state.free_lanes if lane.kind == "tombstone"
    )
    chunk = next(
        chunk
        for chunk in deleted.state.base.chunks
        if chunk.chunk_id == tombstone.location[1]
    )
    slot = tombstone.location[2]
    assert chunk.values[slot] == 0
    assert chunk.column_indices[slot] == 0
    assert chunk.slot_owner_rows[slot] == 0
    assert chunk.slot_kinds[slot] == "tombstone"
    assert deleted.facts.ci_patch_entries == 0

    reused = advance_publication(
        deleted.state,
        _window(NetUpdate(0, 4, 0, 6), index=1),
    )

    assert decode_state(reused.state) == {
        (0, 1): 2,
        (0, 2): 3,
        (0, 4): 6,
        (1, 0): 4,
        (1, 1): 5,
    }
    assert reused.facts.absorbed_tombstone == 1
    assert reused.facts.ci_patch_entries == 1
    assert tombstone.location not in {
        lane.location for lane in reused.state.free_lanes
    }
    assert_strategy_invariants(reused.state)


def test_padding_lane_is_consumed_before_overflow_rebuild() -> None:
    state = initialize_strategy(
        "PaddingReuse-CSSC",
        {(0, 0): 1, (0, 1): 2, (0, 2): 3, (1, 0): 4, (1, 1): 5},
        rows=2,
        cols=6,
        effective_slots=8,
        partition_rows=2,
        max_row_nnz=6,
    )

    transition = advance_publication(
        state,
        _window(NetUpdate(1, 2, 0, 6), NetUpdate(1, 3, 0, 7)),
    )

    assert transition.facts.absorbed_natural_padding == 1
    assert transition.facts.overflow == 1
    assert transition.facts.overflow_rows == (1,)
    assert len(transition.facts.overflow_rows) == transition.facts.overflow
    assert transition.facts.rebuilt_ciphertexts > 0
    assert transition.facts.rebuilt_output_block_ids == ("base-h000000",)
    assert decode_state(transition.state) == {
        **state.logical,
        (1, 2): 6,
        (1, 3): 7,
    }
    assert_strategy_invariants(transition.state)


def test_reserved_slack_is_a_distinct_real_lane_and_follows_natural_padding() -> None:
    logical = {(0, 0): 1, (0, 1): 2, (0, 2): 3, (1, 0): 4, (1, 1): 5}
    padding = initialize_strategy(
        "PaddingReuse-CSSC",
        logical,
        rows=2,
        cols=6,
        effective_slots=8,
        partition_rows=2,
        max_row_nnz=6,
        reserved_slack_beta=0.5,
    )
    reserved = initialize_strategy(
        "ReservedSlack-CSSC",
        logical,
        rows=2,
        cols=6,
        effective_slots=8,
        partition_rows=2,
        max_row_nnz=6,
        reserved_slack_beta=0.5,
    )

    assert padding.base.blocks[0].physical_row_capacities == (3, 2)
    assert reserved.base.blocks[0].physical_row_capacities == (5, 3)
    reserved_lanes = [lane for lane in reserved.free_lanes if lane.kind == "reserved"]
    assert len(reserved_lanes) == 3
    for lane in reserved_lanes:
        chunk = next(
            chunk
            for chunk in reserved.base.chunks
            if chunk.chunk_id == lane.location[1]
        )
        slot = lane.location[2]
        assert chunk.column_indices[slot] == -1
        assert chunk.values[slot] == 0
        assert chunk.slot_owner_rows[slot] == lane.row

    first = advance_publication(reserved, _window(NetUpdate(1, 2, 0, 6)))
    second = advance_publication(
        first.state, _window(NetUpdate(1, 3, 0, 7), index=1)
    )

    assert first.facts.absorbed_natural_padding == 1
    assert first.facts.absorbed_reserved == 0
    assert first.state.base.blocks[0].physical_row_capacities == (5, 4)
    assert second.facts.absorbed_natural_padding == 0
    assert second.facts.absorbed_reserved == 1
    assert second.facts.overflow == 0
    assert decode_state(second.state) == {**logical, (1, 2): 6, (1, 3): 7}


def test_positive_reserved_slack_materializes_and_charges_an_empty_row_lane() -> None:
    state = initialize_strategy(
        "ReservedSlack-CSSC",
        {(0, 0): 1},
        rows=2,
        cols=3,
        effective_slots=2,
        partition_rows=2,
        reserved_slack_beta=1.0,
    )

    transition = advance_publication(state, _window(queries=1))

    assert state.base.blocks[0].physical_row_capacities == (2, 1)
    empty_row_lanes = [
        lane for lane in state.free_lanes if lane.row == 1 and lane.kind == "reserved"
    ]
    assert len(empty_row_lanes) == 1
    assert transition.output_plan.shares[0].slot_to_logical == ((0, 0), (1, 1))
    assert analyze_output_plan(transition.output_plan).implicit_zero_coordinates == 0


def test_zero_reserved_slack_keeps_empty_row_capacity_at_zero() -> None:
    state = initialize_strategy(
        "ReservedSlack-CSSC",
        {(0, 0): 1},
        rows=2,
        cols=3,
        effective_slots=2,
        partition_rows=2,
        reserved_slack_beta=0.0,
    )

    transition = advance_publication(state, _window(queries=1))

    assert state.base.blocks[0].physical_row_capacities == (1, 0)
    assert all(lane.kind != "reserved" for lane in state.free_lanes)
    assert analyze_output_plan(transition.output_plan).implicit_zero_coordinates == 1


def test_reserved_slack_clamps_rebuilt_capacity_when_a_row_becomes_dense() -> None:
    state = initialize_strategy(
        "ReservedSlack-CSSC",
        {(0, 0): 1},
        rows=1,
        cols=3,
        effective_slots=4,
        partition_rows=1,
        max_row_nnz=3,
        reserved_slack_beta=0.5,
    )
    absorbed = advance_publication(state, _window(NetUpdate(0, 1, 0, 2)))

    dense = advance_publication(
        absorbed.state,
        _window(NetUpdate(0, 2, 0, 3), index=1),
    )

    assert dense.state.base.blocks[0].physical_row_capacities == (3,)
    assert dense.facts.rebuilt_ciphertexts == 1
    assert decode_state(dense.state) == {(0, 0): 1, (0, 1): 2, (0, 2): 3}


def test_mini_cssc_delta_persists_and_tracks_its_actual_coordinate_owner() -> None:
    state = initialize_strategy(
        "Mini-CSSC-Delta",
        {(0, 0): 1, (0, 1): 2, (1, 0): 3, (1, 1): 4},
        rows=2,
        cols=6,
        effective_slots=4,
        partition_rows=2,
        max_row_nnz=6,
    )

    inserted = advance_publication(state, _window(NetUpdate(0, 4, 0, 5)))

    assert inserted.facts.overflow == 1
    assert inserted.facts.overflow_rows == (0,)
    assert inserted.facts.delta_ciphertexts == 1
    assert inserted.state.delta is not None
    assert inserted.state.delta.coord_to_slot.keys() == {(0, 4)}
    assert inserted.state.base.coord_to_slot.keys() == state.base.coord_to_slot.keys()
    assert decode_state(inserted.state) == {**state.logical, (0, 4): 5}

    modified = advance_publication(
        inserted.state,
        _window(NetUpdate(0, 4, 5, -6), index=1),
    )

    assert modified.state.delta_logical == {(0, 4): -6}
    assert modified.state.delta is not None
    assert modified.state.delta.version_id == modified.state.version_id
    assert modified.state.base.coord_to_slot.keys() == state.base.coord_to_slot.keys()
    assert modified.facts.delta_ciphertexts == 1
    assert decode_state(modified.state)[(0, 4)] == -6

    deleted = advance_publication(
        modified.state,
        _window(NetUpdate(0, 4, -6, 0), index=2),
    )

    assert deleted.state.delta is None
    assert deleted.state.delta_logical == {}
    assert deleted.facts.delta_ciphertexts == 0
    assert decode_state(deleted.state) == state.logical
    assert_strategy_invariants(deleted.state)


def test_mini_delta_output_plan_uses_the_real_sparse_delta_row_map() -> None:
    state = initialize_strategy(
        "Mini-CSSC-Delta",
        {(0, 0): 1, (1, 0): 2, (2, 0): 3},
        rows=3,
        cols=5,
        effective_slots=3,
        partition_rows=3,
        max_row_nnz=5,
    )

    transition = advance_publication(state, _window(NetUpdate(2, 4, 0, 6)))

    delta_shares = [
        share
        for share in transition.output_plan.shares
        if share.component_id == "mini-delta"
    ]
    assert len(delta_shares) == 1
    assert delta_shares[0].slot_to_logical == ((0, 2),)


def test_strict_local_repack_rebuilds_only_dirty_fixed_horizontal_blocks() -> None:
    state = initialize_strategy(
        "Strict-LocalRepack",
        {
            (0, 0): 1,
            (0, 1): 2,
            (1, 0): 3,
            (2, 0): 4,
            (3, 0): 5,
            (3, 1): 6,
        },
        rows=4,
        cols=6,
        effective_slots=4,
        partition_rows=2,
        max_row_nnz=6,
    )
    clean_block = state.base.blocks[1]

    transition = advance_publication(state, _window(NetUpdate(0, 3, 0, 7)))

    assert transition.facts.rebuilt_output_block_ids == ("base-h000000",)
    assert transition.facts.rebuilt_ciphertexts == len(
        transition.state.base.blocks[0].chunks
    )
    assert transition.state.base.blocks[1] == clean_block
    assert transition.state.base.blocks[0] != state.base.blocks[0]
    assert transition.state.repack_count == 1
    assert decode_state(transition.state) == {**state.logical, (0, 3): 7}
    assert_strategy_invariants(transition.state)


def test_periodic_delta_persists_until_the_nonempty_window_period_expires() -> None:
    state = initialize_strategy(
        "PeriodicRepack",
        {(0, 0): 1, (0, 1): 2, (1, 0): 3, (1, 1): 4},
        rows=2,
        cols=6,
        effective_slots=4,
        partition_rows=2,
        max_row_nnz=6,
        periodic_repack_windows=2,
    )

    first = advance_publication(state, _window(NetUpdate(0, 4, 0, 5)))
    query_only = advance_publication(first.state, _window(index=1, queries=9))

    assert first.state.windows_since_repack == 1
    assert first.state.delta_logical == {(0, 4): 5}
    assert first.state.repack_count == 0
    assert query_only.state is first.state
    assert query_only.state.windows_since_repack == 1

    folded = advance_publication(
        query_only.state,
        _window(NetUpdate(1, 4, 0, 6), index=2),
    )

    assert folded.state.windows_since_repack == 0
    assert folded.state.repack_count == 1
    assert folded.state.delta is None
    assert folded.state.delta_logical == {}
    assert folded.facts.delta_ciphertexts == 0
    assert folded.facts.rebuilt_ciphertexts == len(folded.state.base.chunks)
    assert decode_state(folded.state) == {**state.logical, (0, 4): 5, (1, 4): 6}
    assert_strategy_invariants(folded.state)


def test_periodic_full_fold_does_not_also_count_discarded_point_patch_actions() -> None:
    state = initialize_strategy(
        "PeriodicRepack",
        {(0, 0): 1, (0, 1): 2, (1, 0): 3},
        rows=2,
        cols=4,
        effective_slots=4,
        partition_rows=2,
        max_row_nnz=4,
        periodic_repack_windows=2,
    )
    first = advance_publication(state, _window(NetUpdate(0, 0, 1, 4)))

    folded = advance_publication(
        first.state,
        _window(NetUpdate(1, 1, 0, 5), index=1),
    )

    assert folded.facts.rebuilt_ciphertexts == len(folded.state.base.chunks)
    assert folded.facts.ci_full_sync_entries > 0
    assert (
        folded.facts.absorbed_tombstone,
        folded.facts.absorbed_natural_padding,
        folded.facts.absorbed_reserved,
        folded.facts.overflow,
    ) == (0, 0, 0, 0)


def test_packed_coo_batches_overflow_and_reuses_fixed_segment_holes() -> None:
    state = initialize_strategy(
        "Packed-COO-Client-Lane-Delta",
        {(0, 0): 1, (0, 1): 2, (1, 0): 3, (1, 1): 4},
        rows=2,
        cols=8,
        effective_slots=4,
        partition_rows=2,
        max_row_nnz=8,
        packed_coo_segment_capacity=2,
    )

    inserted = advance_publication(
        state,
        _window(
            NetUpdate(0, 4, 0, 5),
            NetUpdate(1, 4, 0, 6),
            NetUpdate(0, 5, 0, 7),
        ),
    )

    assert inserted.facts.overflow == 3
    assert inserted.facts.delta_ciphertexts == 2
    assert len(inserted.state.coo_segments) == 2
    assert all(len(segment.entries) == 2 for segment in inserted.state.coo_segments)
    assert [
        sum(entry is not None for entry in segment.entries)
        for segment in inserted.state.coo_segments
    ] == [2, 1]
    assert len(
        [
            share
            for share in inserted.output_plan.shares
            if share.component_id == "packed-coo-delta"
        ]
    ) == 2

    segment_ids = tuple(segment.segment_id for segment in inserted.state.coo_segments)
    reused = advance_publication(
        inserted.state,
        _window(
            NetUpdate(0, 4, 5, 0),
            NetUpdate(1, 5, 0, -7),
            index=1,
        ),
    )

    assert tuple(segment.segment_id for segment in reused.state.coo_segments) == segment_ids
    assert len(reused.state.coo_segments) == 2
    assert reused.facts.overflow == 0
    assert reused.facts.overflow_rows == ()
    assert reused.facts.delta_ciphertexts == 2
    assert reused.facts.ci_patch_entries == 1
    assert reused.state.delta_logical == {(0, 5): 7, (1, 4): 6, (1, 5): -7}
    assert decode_state(reused.state) == {
        **state.logical,
        (0, 5): 7,
        (1, 4): 6,
        (1, 5): -7,
    }
    assert_strategy_invariants(reused.state)


def test_packed_coo_delete_retains_old_ci_until_one_time_lane_reuse() -> None:
    state = initialize_strategy(
        "Packed-COO-Client-Lane-Delta",
        {(0, 0): 1, (1, 0): 2},
        rows=2,
        cols=8,
        effective_slots=2,
        partition_rows=2,
        max_row_nnz=8,
        packed_coo_segment_capacity=2,
    )
    inserted = advance_publication(
        state,
        _window(NetUpdate(0, 4, 0, 5), NetUpdate(1, 4, 0, 6)),
    )

    deleted = advance_publication(
        inserted.state,
        _window(NetUpdate(0, 4, 5, 0), index=1),
    )

    tombstone = deleted.state.coo_segments[0].entries[0]
    assert tombstone is not None
    assert tombstone.coordinate == (0, 4)
    assert tombstone.value == 0
    assert deleted.facts.ci_patch_entries == 0
    assert deleted.state.delta_logical == {(1, 4): 6}

    reused = advance_publication(
        deleted.state,
        _window(NetUpdate(0, 5, 0, 7), index=2),
    )

    assert reused.state.coo_segments[0].entries[0] is not None
    assert reused.state.coo_segments[0].entries[0].coordinate == (0, 5)
    assert reused.facts.ci_patch_entries == 1
    assert reused.state.delta_logical == {(0, 5): 7, (1, 4): 6}


def test_packed_coo_returns_each_active_entry_lane_for_client_reconstruction() -> None:
    state = initialize_strategy(
        "Packed-COO-Client-Lane-Delta",
        {(0, 0): 1, (1, 0): 2},
        rows=2,
        cols=8,
        effective_slots=3,
        partition_rows=2,
        max_row_nnz=8,
        packed_coo_segment_capacity=3,
    )

    transition = advance_publication(
        state,
        _window(
            NetUpdate(0, 4, 0, 5),
            NetUpdate(1, 4, 0, 6),
            NetUpdate(0, 5, 0, 7),
        ),
    )

    coo_share = next(
        share
        for share in transition.output_plan.shares
        if share.component_id == "packed-coo-delta"
    )
    assert coo_share.slot_to_logical == ((0, 0), (1, 1), (2, 0))
    analysis = analyze_output_plan(transition.output_plan)
    assert (
        analysis.result_ciphertexts,
        analysis.masked_result_ciphertexts,
        analysis.client_reorder_elements,
        analysis.client_modular_additions,
        analysis.mask_random_elements,
        analysis.mask_mapped_elements,
    ) == (2, 2, 5, 3, 3, 5)


def test_all_active_components_advance_to_one_version() -> None:
    state = initialize_strategy(
        "Packed-COO-Client-Lane-Delta",
        {(0, 0): 1, (1, 0): 2},
        rows=2,
        cols=6,
        effective_slots=2,
        partition_rows=2,
        max_row_nnz=6,
        packed_coo_segment_capacity=2,
    )
    first = advance_publication(state, _window(NetUpdate(0, 3, 0, 4)))
    second = advance_publication(
        first.state, _window(NetUpdate(1, 3, 0, 5), index=1)
    )

    assert second.state.base.version_id == second.state.version_id
    assert {
        segment.version_id for segment in second.state.coo_segments
    } == {second.state.version_id}
    assert second.facts.active_component_ids == ("base", "packed-coo-delta")


@pytest.mark.parametrize("strategy", STRATEGIES)
def test_every_strategy_transition_decodes_the_same_mixed_window(strategy: str) -> None:
    state = initialize_strategy(
        strategy,
        {(0, 0): 1, (0, 1): 2, (1, 0): 3, (2, 0): 4},
        rows=3,
        cols=6,
        effective_slots=6,
        partition_rows=3,
        max_row_nnz=6,
        reserved_slack_beta=0.5,
        periodic_repack_windows=3,
        packed_coo_segment_capacity=3,
    )
    expected = {(0, 0): -1, (1, 0): 3, (1, 4): 6, (2, 0): 4}

    transition = advance_publication(
        state,
        _window(
            NetUpdate(0, 0, 1, -1),
            NetUpdate(0, 1, 2, 0),
            NetUpdate(1, 4, 0, 6),
        ),
    )

    assert transition.state.version_ordinal == 1
    assert transition.state.version_id == "v00000001"
    assert decode_state(transition.state) == expected
    assert decode_state(state) == {(0, 0): 1, (0, 1): 2, (1, 0): 3, (2, 0): 4}
    assert transition.facts.updates == 3
    assert_strategy_invariants(transition.state)


@pytest.mark.parametrize("strategy", STRATEGIES)
def test_updated_strategy_adopts_the_validator_owned_logical_mapping_without_recopied_state(
    strategy: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = initialize_strategy(
        strategy,
        {(0, 0): 1, (1, 0): 2},
        rows=2,
        cols=4,
        effective_slots=4,
        partition_rows=2,
        max_row_nnz=4,
        reserved_slack_beta=0.5,
        periodic_repack_windows=1,
        packed_coo_segment_capacity=2,
    )
    original_logical = dict(state.logical)
    candidates: list[dict[tuple[int, int], int]] = []
    real_validate = strategy_state_module._validated_candidate

    def record_candidate(*args: object, **kwargs: object) -> dict[tuple[int, int], int]:
        candidate = real_validate(*args, **kwargs)  # type: ignore[arg-type]
        candidates.append(candidate)
        return candidate

    monkeypatch.setattr(strategy_state_module, "_validated_candidate", record_candidate)

    transition = advance_publication(state, _window(NetUpdate(0, 0, 1, 3)))

    assert transition.state.logical is candidates[0]
    assert transition.state.logical is not state.logical
    transition.state.logical[(1, 1)] = 4
    assert state.logical == original_logical


def test_query_only_transition_reuses_the_existing_logical_mapping_without_copying(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = initialize_strategy(
        "PaddingReuse-CSSC",
        {(0, 0): 1, (1, 0): 2},
        rows=2,
        cols=4,
        effective_slots=4,
        partition_rows=2,
    )
    candidates: list[dict[tuple[int, int], int]] = []
    real_validate = strategy_state_module._validated_candidate

    def record_candidate(*args: object, **kwargs: object) -> dict[tuple[int, int], int]:
        candidate = real_validate(*args, **kwargs)  # type: ignore[arg-type]
        candidates.append(candidate)
        return candidate

    monkeypatch.setattr(strategy_state_module, "_validated_candidate", record_candidate)

    transition = advance_publication(state, _window(queries=3))

    assert transition.state is state
    assert len(candidates) == 1
    assert candidates[0] is state.logical


def test_invariant_rejects_logical_metadata_that_disagrees_with_components() -> None:
    state = initialize_strategy(
        "PaddingReuse-CSSC",
        {(0, 0): 1, (1, 0): 2},
        rows=2,
        cols=3,
        effective_slots=2,
        partition_rows=2,
    )

    with pytest.raises(AssertionError, match="decoded components"):
        assert_strategy_invariants(replace(state, logical={(0, 0): 1}))


def test_advance_fails_closed_on_a_version_inconsistent_input_snapshot() -> None:
    state = initialize_strategy(
        "PaddingReuse-CSSC",
        {(0, 0): 1},
        rows=1,
        cols=2,
        effective_slots=2,
        partition_rows=1,
    )
    inconsistent = replace(state, version_id="v00000001")

    with pytest.raises(AssertionError, match="version identifier"):
        advance_publication(inconsistent, _window(queries=1))


def test_tail_lanes_are_never_exposed_as_reusable_capacity() -> None:
    state = initialize_strategy(
        "PaddingReuse-CSSC",
        {(0, 0): 1, (1, 0): 2},
        rows=2,
        cols=4,
        effective_slots=4,
        partition_rows=2,
    )
    reusable = {lane.location for lane in state.free_lanes}

    for chunk in state.base.chunks:
        for slot, kind in enumerate(chunk.slot_kinds):
            if kind != "tail":
                continue
            assert chunk.slot_owner_rows[slot] is None
            assert chunk.column_indices[slot] == -1
            assert chunk.values[slot] == 0
            assert (state.base.component_id, chunk.chunk_id, slot) not in reusable


@pytest.mark.parametrize("strategy", ("Strict-LocalRepack", "PeriodicRepack"))
def test_repack_can_publish_an_implicit_zero_logical_row(strategy: str) -> None:
    state = initialize_strategy(
        strategy,
        {(0, 0): 1, (1, 0): 2},
        rows=2,
        cols=3,
        effective_slots=2,
        partition_rows=2,
        periodic_repack_windows=1,
    )

    transition = advance_publication(state, _window(NetUpdate(0, 0, 1, 0)))

    assert decode_state(transition.state) == {(1, 0): 2}
    assert {
        logical
        for share in transition.output_plan.shares
        for _, logical in share.slot_to_logical
    } == {1}
    assert_strategy_invariants(transition.state)


@pytest.mark.parametrize("strategy", STRATEGIES)
def test_public_transition_rejects_a_noncanonical_noop_update(strategy: str) -> None:
    state = initialize_strategy(
        strategy,
        {(0, 0): 1},
        rows=1,
        cols=2,
        effective_slots=2,
        partition_rows=1,
        packed_coo_segment_capacity=2,
    )

    with pytest.raises(ValueError, match="no-op"):
        advance_publication(state, _window(NetUpdate(0, 0, 1, 1)))


def test_transition_facts_reject_mismatched_overflow_rows() -> None:
    with pytest.raises(ValueError, match="overflow_rows"):
        TransitionFacts(updates=1, query_count=0, overflow=1)
