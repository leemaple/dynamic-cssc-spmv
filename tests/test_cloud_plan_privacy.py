from __future__ import annotations

from dataclasses import replace

import pytest

from dynamic_cssc.cloud_execution_plan import (
    AddF1MMask,
    CloudExecutionPlanError,
    ReturnResult,
    build_fixed_stride_cloud_program,
    canonical_cloud_program_bytes,
    canonical_cloud_program_payload,
    validate_cloud_program,
)
from dynamic_cssc.output_plan import OutputPlan, OutputShare, analyze_output_plan
from dynamic_cssc.strong_packed_coo import (
    CloudPageShape,
    StrongEntry,
    advance_segmented_delta,
    cloud_page_shapes,
    initialize_segmented_delta,
)


def _owner_row_permuted_states():
    initial = initialize_segmented_delta(
        rows=6,
        cols=64,
        effective_slots=8,
        segment_width=2,
        matrix_value_bound=20,
        version_id="v0",
    )
    left = advance_segmented_delta(
        initial,
        delta_updates=(),
        overflow_entries=tuple(StrongEntry(row, 16 + row, row + 1) for row in range(6)),
        version_id="v1",
    ).state
    owner_permutation = (5, 3, 1, 4, 2, 0)
    right = replace(
        left,
        segments=tuple(
            replace(
                segment,
                owner_row=owner_permutation[segment.owner_row],
                entries=tuple(
                    None if entry is None else replace(entry, row=owner_permutation[entry.row])
                    for entry in segment.entries
                ),
            )
            for segment in left.segments
        ),
    )
    return left, right


def _program_from_public_page_shapes(
    shapes: tuple[CloudPageShape, ...],
):
    assert shapes
    first = shapes[0]
    assert all(
        shape.page_id == f"page-{ordinal:06d}"
        and shape.page_ordinal == ordinal
        and shape.slot_count == first.slot_count
        and shape.segment_width == first.segment_width
        and shape.segment_count == first.segment_count
        for ordinal, shape in enumerate(shapes)
    )
    return build_fixed_stride_cloud_program(
        page_count=len(shapes),
        effective_slots=first.slot_count,
        segment_width=first.segment_width,
    )


def test_private_owner_row_permutation_does_not_change_program_bytes() -> None:
    left, right = _owner_row_permuted_states()
    left_shapes = cloud_page_shapes(left)
    right_shapes = cloud_page_shapes(right)

    assert tuple(segment.owner_row for segment in left.segments) != tuple(
        segment.owner_row for segment in right.segments
    )
    assert left_shapes == right_shapes
    assert canonical_cloud_program_bytes(_program_from_public_page_shapes(left_shapes)) == (
        canonical_cloud_program_bytes(_program_from_public_page_shapes(right_shapes))
    )


def test_built_cloud_program_payload_has_only_closed_public_keys() -> None:
    left, _ = _owner_row_permuted_states()
    program = _program_from_public_page_shapes(cloud_page_shapes(left))
    payload = canonical_cloud_program_payload(program)
    encoded = canonical_cloud_program_bytes(program).lower()

    assert set(payload) == {
        "ciphertext_inputs",
        "format",
        "nodes",
        "plaintext_masks",
        "result_ids",
        "rotation_catalog",
        "slot_count",
    }
    for forbidden in (
        b"rowmap",
        b"row_map",
        b"columnindex",
        b"column_index",
        b"logical_coordinate",
        b"logical_row",
        b"private_mapping",
        b"slot_to_logical",
    ):
        assert forbidden not in encoded


def test_private_overlap_does_not_control_program_bytes_or_f1m_schedule() -> None:
    private_overlap = OutputPlan(
        logical_output_size=2,
        slot_count=4,
        shares=(
            OutputShare("component-0", "block", ((0, 0),)),
            OutputShare("component-1", "block", ((0, 0),)),
        ),
    )
    private_non_overlap = OutputPlan(
        logical_output_size=2,
        slot_count=4,
        shares=(
            OutputShare("component-0", "block", ((0, 0),)),
            OutputShare("component-1", "block", ((0, 1),)),
        ),
    )
    overlapping = build_fixed_stride_cloud_program(
        page_count=2,
        effective_slots=4,
        segment_width=2,
    )
    non_overlapping = build_fixed_stride_cloud_program(
        page_count=2,
        effective_slots=4,
        segment_width=2,
    )

    assert analyze_output_plan(private_overlap).overlap_coordinates == 1
    assert analyze_output_plan(private_non_overlap).overlap_coordinates == 0
    assert canonical_cloud_program_bytes(overlapping) == canonical_cloud_program_bytes(
        non_overlapping
    )
    assert sum(isinstance(node, AddF1MMask) for node in overlapping.nodes) == 2
    assert all(
        not isinstance(node, AddF1MMask) or node.mask_role == "opaque-zero-sum"
        for node in non_overlapping.nodes
    )


def test_one_encrypted_f1m_operand_cannot_be_reused_for_two_results() -> None:
    program = build_fixed_stride_cloud_program(
        page_count=2,
        effective_slots=4,
        segment_width=2,
    )
    reused_mask_nodes = tuple(
        replace(node, mask_ciphertext_id="ct-f1m-000000")
        if isinstance(node, AddF1MMask) and node.result_id == "ssa-masked-000001"
        else node
        for node in program.nodes
    )

    with pytest.raises(CloudExecutionPlanError, match="F1M mask operand.*exactly once"):
        validate_cloud_program(
            replace(
                program,
                ciphertext_inputs=tuple(
                    operand
                    for operand in program.ciphertext_inputs
                    if operand.ciphertext_id != "ct-f1m-000001"
                ),
                nodes=reused_mask_nodes,
            )
        )


def test_return_result_cannot_bypass_its_single_f1m_addition() -> None:
    program = build_fixed_stride_cloud_program(
        page_count=2,
        effective_slots=4,
        segment_width=2,
    )
    bypassed_nodes = tuple(
        replace(node, ciphertext_id="ssa-selected-000000")
        if isinstance(node, ReturnResult) and node.result_id == "page-000000"
        else node
        for node in program.nodes
    )

    with pytest.raises(CloudExecutionPlanError, match="directly return one AddF1MMask"):
        validate_cloud_program(replace(program, nodes=bypassed_nodes))
