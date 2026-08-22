from __future__ import annotations

import copy
from dataclasses import fields

import pytest

from dynamic_cssc.events import NetUpdate
from dynamic_cssc.strong_packed_coo import (
    ClientBPageMetadata,
    StrongEntry,
    advance_segmented_delta,
    client_b_page_metadata,
    cloud_page_shapes,
    decode_segmented_delta,
    initialize_segmented_delta,
)


def _empty_state(*, slots: int = 8, width: int = 2):
    return initialize_segmented_delta(
        rows=4,
        cols=32,
        effective_slots=slots,
        segment_width=width,
        matrix_value_bound=20,
        version_id="v0",
    )


def test_overflow_is_packed_into_private_fixed_width_single_row_segments() -> None:
    transition = advance_segmented_delta(
        _empty_state(),
        delta_updates=(),
        overflow_entries=(
            StrongEntry(2, 19, 5),
            StrongEntry(0, 17, 3),
            StrongEntry(2, 23, -4),
            StrongEntry(1, 31, 7),
        ),
        version_id="v1",
    )

    assert decode_segmented_delta(transition.state) == {
        (0, 17): 3,
        (1, 31): 7,
        (2, 19): 5,
        (2, 23): -4,
    }
    assert [segment.owner_row for segment in transition.state.segments] == [0, 1, 2]
    assert [segment.segment_ordinal for segment in transition.state.segments] == [0, 1, 2]
    assert all(len(segment.entries) == 2 for segment in transition.state.segments)
    assert all(
        entry is None or entry.row == segment.owner_row
        for segment in transition.state.segments
        for entry in segment.entries
    )
    assert transition.new_segment_count == 3
    assert transition.new_page_count == 1
    assert transition.ci_full_sync_entries == 8
    assert transition.ci_patch_entries == 0

    shapes = cloud_page_shapes(transition.state)
    assert len(shapes) == 1
    assert (shapes[0].slot_count, shapes[0].segment_width, shapes[0].segment_count) == (
        8,
        2,
        4,
    )
    assert not {
        "row",
        "logical_row",
        "column_indices",
        "global_column_indices",
        "ci",
    } & {field.name for field in fields(shapes[0])}
    metadata = client_b_page_metadata(transition.state)[0]
    assert metadata.version_id == transition.state.version_id == "v1"
    assert metadata.global_column_indices == (
        17,
        -1,
        31,
        -1,
        19,
        23,
        -1,
        -1,
    )


@pytest.mark.parametrize("width", (1, 3, 6, 16))
def test_segment_width_must_be_a_power_of_two_that_fits_the_page(width: int) -> None:
    with pytest.raises(ValueError, match="power of two"):
        _empty_state(slots=8, width=width)


def test_frozen_segment_width_accepts_128_but_rejects_127() -> None:
    assert _empty_state(slots=256, width=128).segment_width == 128
    with pytest.raises(ValueError, match="power of two"):
        _empty_state(slots=256, width=127)


def test_ci_accounting_diffs_existing_pages_but_full_syncs_each_new_page_once() -> None:
    first = advance_segmented_delta(
        _empty_state(slots=8, width=4),
        delta_updates=(),
        overflow_entries=(StrongEntry(0, 17, 3),),
        version_id="v1",
    )
    appended = advance_segmented_delta(
        first.state,
        delta_updates=(),
        overflow_entries=(StrongEntry(1, 18, 4), StrongEntry(1, 19, 5)),
        version_id="v2",
    )

    assert appended.new_segment_count == 1
    assert appended.new_page_count == 0
    assert appended.ci_full_sync_entries == 0
    assert appended.ci_patch_entries == 2
    assert client_b_page_metadata(appended.state) == (
        ClientBPageMetadata(
            page_id="page-000000",
            version_id="v2",
            global_column_indices=(17, -1, -1, -1, 18, 19, -1, -1),
        ),
    )

    new_page = advance_segmented_delta(
        appended.state,
        delta_updates=(),
        overflow_entries=(StrongEntry(2, 20, 6),),
        version_id="v3",
    )

    assert new_page.new_segment_count == 1
    assert new_page.new_page_count == 1
    assert new_page.ci_full_sync_entries == 8
    assert new_page.ci_patch_entries == 0
    assert {metadata.version_id for metadata in client_b_page_metadata(new_page.state)} == {"v3"}


def test_delete_retains_ci_and_only_the_owner_row_can_reuse_the_tombstone() -> None:
    inserted = advance_segmented_delta(
        _empty_state(slots=4),
        delta_updates=(),
        overflow_entries=(StrongEntry(0, 17, 3), StrongEntry(0, 18, 4)),
        version_id="v1",
    )
    deleted = advance_segmented_delta(
        inserted.state,
        delta_updates=(NetUpdate(0, 17, 3, 0),),
        overflow_entries=(),
        version_id="v2",
    )

    tombstone = deleted.state.segments[0].entries[0]
    assert tombstone == StrongEntry(0, 17, 0)
    assert decode_segmented_delta(deleted.state) == {(0, 18): 4}
    assert client_b_page_metadata(deleted.state)[0].global_column_indices == (
        17,
        18,
        -1,
        -1,
    )

    other_row = advance_segmented_delta(
        deleted.state,
        delta_updates=(),
        overflow_entries=(StrongEntry(1, 20, 5),),
        version_id="v3",
    )
    assert len(other_row.state.segments) == 2
    assert other_row.new_segment_count == 1
    assert other_row.state.segments[0].entries[0] == tombstone

    same_row = advance_segmented_delta(
        other_row.state,
        delta_updates=(),
        overflow_entries=(StrongEntry(0, 21, 6),),
        version_id="v4",
    )
    assert len(same_row.state.segments) == 2
    assert same_row.state.segments[0].entries[0] == StrongEntry(0, 21, 6)
    assert same_row.ci_patch_entries == 1
    assert same_row.new_segment_count == 0


def test_exact_coordinate_reactivation_prefers_its_tombstone_without_ci_patch() -> None:
    inserted = advance_segmented_delta(
        _empty_state(slots=4),
        delta_updates=(),
        overflow_entries=(StrongEntry(0, 17, 3), StrongEntry(0, 18, 4)),
        version_id="v1",
    )
    deleted = advance_segmented_delta(
        inserted.state,
        delta_updates=(NetUpdate(0, 17, 3, 0), NetUpdate(0, 18, 4, 0)),
        overflow_entries=(),
        version_id="v2",
    )

    reactivated = advance_segmented_delta(
        deleted.state,
        delta_updates=(),
        overflow_entries=(StrongEntry(0, 18, 9),),
        version_id="v3",
    )

    assert reactivated.state.segments[0].entries == (
        StrongEntry(0, 17, 0),
        StrongEntry(0, 18, 9),
    )
    assert reactivated.ci_patch_entries == 0


def test_same_row_hole_is_reused_before_allocating_another_segment() -> None:
    first = advance_segmented_delta(
        _empty_state(slots=4),
        delta_updates=(),
        overflow_entries=(StrongEntry(3, 24, 5),),
        version_id="v1",
    )
    assert first.state.segments[0].entries == (StrongEntry(3, 24, 5), None)

    reused = advance_segmented_delta(
        first.state,
        delta_updates=(),
        overflow_entries=(StrongEntry(3, 25, 6),),
        version_id="v2",
    )

    assert len(reused.state.segments) == 1
    assert reused.state.segments[0].entries == (
        StrongEntry(3, 24, 5),
        StrongEntry(3, 25, 6),
    )
    assert reused.ci_patch_entries == 1
    assert reused.new_segment_count == 0


def test_modify_delete_insert_across_waves_is_exact_and_failure_is_atomic() -> None:
    first = advance_segmented_delta(
        _empty_state(),
        delta_updates=(),
        overflow_entries=(StrongEntry(2, 30, 5), StrongEntry(2, 31, 6)),
        version_id="v1",
    )
    second = advance_segmented_delta(
        first.state,
        delta_updates=(NetUpdate(2, 30, 5, -7), NetUpdate(2, 31, 6, 0)),
        overflow_entries=(StrongEntry(2, 29, 8),),
        version_id="v2",
    )
    assert decode_segmented_delta(second.state) == {(2, 29): 8, (2, 30): -7}
    assert decode_segmented_delta(first.state) == {(2, 30): 5, (2, 31): 6}
    assert second.ci_full_sync_entries == 0
    assert second.ci_patch_entries == 1

    snapshot = copy.deepcopy(second.state)
    metadata_snapshot = client_b_page_metadata(second.state)
    with pytest.raises(ValueError, match="before"):
        advance_segmented_delta(
            second.state,
            delta_updates=(NetUpdate(2, 30, 999, 1),),
            overflow_entries=(),
            version_id="v3",
        )
    assert second.state == snapshot
    assert client_b_page_metadata(second.state) == metadata_snapshot


def test_multiple_fixed_pages_preserve_tail_and_are_row_label_oblivious() -> None:
    left = advance_segmented_delta(
        _empty_state(slots=10, width=4),
        delta_updates=(),
        overflow_entries=tuple(StrongEntry(row, 16 + row, row + 1) for row in range(4)),
        version_id="v1",
    ).state
    right = advance_segmented_delta(
        _empty_state(slots=10, width=4),
        delta_updates=(),
        overflow_entries=tuple(StrongEntry(row, 16 + row, 4 - row) for row in reversed(range(4))),
        version_id="v1",
    ).state

    assert cloud_page_shapes(left) == cloud_page_shapes(right)
    assert [(shape.page_id, shape.segment_count) for shape in cloud_page_shapes(left)] == [
        ("page-000000", 2),
        ("page-000001", 2),
    ]
    assert {segment.slot_start for segment in left.segments} == {0, 4}
