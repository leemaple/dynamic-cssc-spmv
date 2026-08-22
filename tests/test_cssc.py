from __future__ import annotations

import pytest

from dynamic_cssc.cssc import build_cssc_layout, output_plan_for, publish_component
from dynamic_cssc.output_plan import analyze_output_plan


def test_cssc_proxy_sorts_rows_and_exposes_real_padding() -> None:
    layout = build_cssc_layout([1, 4, 2], effective_slots=8)
    assert layout.logical_row_order == (1, 2, 0)
    assert layout.ciphertext_count >= 1
    assert sum(len(slots) for slots in layout.padding_chunk_ids_by_logical_row) > 0


def test_cssc_proxy_rejects_too_tall_column() -> None:
    try:
        build_cssc_layout([1] * 9, effective_slots=8)
    except ValueError as exc:
        assert "exceeds effective slot capacity" in str(exc)
    else:
        raise AssertionError("expected capacity failure")


def test_non_power_of_two_width_counts_all_rotation_terms() -> None:
    layout = build_cssc_layout([7], effective_slots=7)

    assert len(layout.chunks) == 1
    assert layout.chunks[0].width == 7
    assert layout.chunks[0].aggregation_rotations_proxy == 4


def test_real_cssc_preflight_preserves_global_columns_across_horizontal_blocks() -> None:
    state = {(row, row): 1 for row in range(257)}
    state[(0, 520)] = 7

    published = publish_component(
        state,
        rows=257,
        cols=521,
        effective_slots=256,
        version_id="preflight-v1",
        component_prefix="base",
    )

    assert tuple(block.row_map for block in published.blocks) == (
        tuple(range(256)),
        (256,),
    )
    assert len(published.coord_to_slot) == len(state)
    assert set(published.coord_to_slot) == set(state)
    component_id, chunk_id, slot = published.coord_to_slot[(0, 520)]
    high_column_chunk = next(chunk for chunk in published.chunks if chunk.chunk_id == chunk_id)
    assert component_id == "base"
    assert high_column_chunk.column_indices[slot] == 520
    assert high_column_chunk.column_indices[slot] != 520 % 256
    assert published.query_ciphertext_count == published.ciphertext_count == len(
        published.chunks
    )
    assert all(
        len(chunk.values)
        == len(chunk.column_indices)
        == len(chunk.slot_coordinates)
        == len(chunk.slot_owner_rows)
        == len(chunk.slot_kinds)
        == 256
        for chunk in published.chunks
    )


def test_output_plan_uses_each_components_real_row_map() -> None:
    base = publish_component(
        {(0, 0): 1, (1, 0): 1, (1, 1): 1, (1, 2): 1, (2, 0): 1, (2, 1): 1},
        rows=3,
        cols=4,
        effective_slots=8,
        version_id="v7",
        component_prefix="base",
    )
    delta = publish_component(
        {(0, 0): 1, (0, 1): 1, (1, 0): 1, (2, 0): 1},
        rows=3,
        cols=4,
        effective_slots=8,
        version_id="v7",
        component_prefix="delta",
    )

    plan = output_plan_for((base, delta))

    assert tuple((share.component_id, share.slot_to_logical) for share in plan.shares) == (
        ("base", ((0, 1), (1, 2), (2, 0))),
        ("delta", ((0, 0), (1, 1), (2, 2))),
    )


def test_sparse_component_maps_only_rows_with_physical_contributions() -> None:
    common = {
        "rows": 4,
        "cols": 4,
        "effective_slots": 4,
        "version_id": "v8",
    }
    base = publish_component(
        {(row, row): 1 for row in range(4)},
        **common,
        component_prefix="base",
    )
    delta = publish_component(
        {(0, 0): 2},
        **common,
        component_prefix="delta",
    )

    plan = output_plan_for((base, delta))
    analysis = analyze_output_plan(plan)
    delta_share = next(share for share in plan.shares if share.component_id == "delta")

    assert delta_share.slot_to_logical == ((0, 0),)
    assert analysis.overlap_coordinates == 1
    assert analysis.mask_random_elements == 1


def test_output_plan_allows_components_with_different_horizontal_partitions() -> None:
    common = {
        "state": {(row, row): 1 for row in range(4)},
        "rows": 4,
        "cols": 4,
        "effective_slots": 4,
        "version_id": "v7",
    }
    base = publish_component(
        **common,
        component_prefix="base",
        partition_rows=2,
    )
    delta = publish_component(
        **common,
        component_prefix="delta",
        partition_rows=4,
    )

    plan = output_plan_for((base, delta))

    assert tuple(share.slot_to_logical for share in plan.shares) == (
        ((0, 0), (1, 1)),
        ((0, 2), (1, 3)),
        ((0, 0), (1, 1), (2, 2), (3, 3)),
    )


def test_reserved_capacity_has_real_column_major_slots_with_sentinels() -> None:
    published = publish_component(
        {(0, 8): 4, (1, 2): 5, (1, 9): 7, (2, 7): 6},
        rows=3,
        cols=10,
        effective_slots=8,
        version_id="v1",
        component_prefix="reserved",
        physical_capacities=(4, 2, 1),
    )

    first, second = published.chunks
    assert first.column_indices == (8, 2, 7, -1, 9, -1, -1, -1)
    assert first.values == (4, 5, 6, 0, 7, 0, 0, 0)
    assert first.slot_coordinates == (
        (0, 8),
        (1, 2),
        (2, 7),
        None,
        (1, 9),
        None,
        None,
        None,
    )
    assert first.slot_owner_rows == (0, 1, 2, 0, 1, 2, None, None)
    assert first.slot_kinds == (
        "actual",
        "actual",
        "actual",
        "reserved",
        "actual",
        "natural-padding",
        "tail",
        "tail",
    )
    assert first.reserved_slots == 1
    assert second.column_indices == (-1,) * 8
    assert second.reserved_slots == 2
    assert second.slot_owner_rows == (0, 0, None, None, None, None, None, None)
    assert second.slot_kinds == ("reserved", "reserved", *("tail",) * 6)
    assert tuple(location[2] for location in published.reserved_slots_by_row[0]) == (3, 0, 1)
    assert tuple(location[2] for location in published.natural_padding_slots_by_row[2]) == (5,)


def test_output_plan_represents_unmaterialized_rows_as_implicit_zero() -> None:
    partial = publish_component(
        {(0, 0): 1},
        rows=3,
        cols=2,
        effective_slots=2,
        partition_rows=2,
        version_id="v1",
        component_prefix="partial",
    )

    analysis = analyze_output_plan(output_plan_for((partial,)))

    assert analysis.result_ciphertexts == 1
    assert analysis.implicit_zero_coordinates == 2


def test_real_cssc_publication_is_deterministic_and_keeps_signed_values() -> None:
    items = [((1, 9), -7), ((0, 3), 2), ((1, 1), 4), ((2, 5), -1)]
    kwargs = {
        "rows": 3,
        "cols": 10,
        "effective_slots": 8,
        "version_id": "v2",
        "component_prefix": "base",
        "physical_capacities": (2, 3, 1),
    }

    forward = publish_component(dict(items), **kwargs)
    reverse = publish_component(dict(reversed(items)), **kwargs)

    assert forward == reverse
    assert tuple(chunk.chunk_id for chunk in forward.chunks) == (
        "base-h000000-c000000",
        "base-h000000-c000001",
    )
    assert {value for chunk in forward.chunks for value in chunk.values} >= {-7, -1, 2, 4}


@pytest.mark.parametrize(
    ("state", "overrides", "message"),
    [
        ({(2, 0): 1}, {}, "row is outside"),
        ({(0, 3): 1}, {}, "global column is outside"),
        ({(True, 0): 1}, {}, "coordinates"),
        ({(0, 0): 0}, {}, "nonzero integers"),
        ({(0, 0): True}, {}, "nonzero integers"),
        ({(0, 0): 1}, {"physical_capacities": (0, 0)}, "physical capacity"),
        ({(0, 0): 1}, {"physical_capacities": (1,)}, "exactly one entry"),
        ({(0, 0): 1}, {"partition_rows": 5}, "partition_rows"),
        ({(0, 0): 1}, {"version_id": "not printable"}, "version_id"),
    ],
)
def test_real_cssc_publication_rejects_invalid_contract_inputs(
    state: object,
    overrides: dict[str, object],
    message: str,
) -> None:
    kwargs: dict[str, object] = {
        "rows": 2,
        "cols": 3,
        "effective_slots": 4,
        "version_id": "v1",
        "component_prefix": "base",
    }
    kwargs.update(overrides)

    with pytest.raises(ValueError, match=message):
        publish_component(state, **kwargs)  # type: ignore[arg-type]


def test_real_cssc_chunks_keep_the_frozen_non_power_of_two_rotation_formula() -> None:
    published = publish_component(
        {(0, column): 1 for column in range(7)},
        rows=1,
        cols=7,
        effective_slots=7,
        version_id="v1",
        component_prefix="base",
    )

    assert published.chunks[0].width == 7
    assert published.chunks[0].aggregation_rotations_proxy == 4
