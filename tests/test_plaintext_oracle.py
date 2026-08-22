from __future__ import annotations

from dataclasses import replace

import pytest

from dynamic_cssc.cloud_execution_plan import (
    CLOUD_PROGRAM_FORMAT,
    EXECUTION_BINDING_FORMAT,
    AddCiphertexts,
    AddF1MMask,
    CiphertextInput,
    CloudExecutionPlan,
    CloudProgram,
    ExecutionBinding,
    MultiplyCiphertexts,
    MultiplyPlaintextMask,
    PlaintextMask,
    Relinearize,
    ReturnResult,
    Rotate,
    RotationCatalog,
    build_fixed_stride_cloud_program,
    cloud_program_digest,
)
from dynamic_cssc.events import NetUpdate
from dynamic_cssc.output_plan import (
    OutputPlan,
    OutputShare,
    analyze_output_plan,
)
from dynamic_cssc.plaintext_oracle import (
    direct_spmv,
    execute_cloud_plan,
    reconstruct_output,
)
from dynamic_cssc.strong_packed_coo import (
    STRONG_COMPONENT_ID,
    StrongEntry,
    advance_segmented_delta,
    client_b_page_metadata,
    cloud_page_shapes,
    decode_segmented_delta,
    initialize_segmented_delta,
    post_aggregation_output_shares,
)


def _fixed_stride_plan() -> CloudExecutionPlan:
    program = CloudProgram(
        format=CLOUD_PROGRAM_FORMAT,
        slot_count=10,
        ciphertext_inputs=(
            CiphertextInput("value-page", "value", 10),
            CiphertextInput("query-page", "query", 10),
            CiphertextInput("blind", "f1m-mask", 10),
        ),
        plaintext_masks=(
            PlaintextMask(
                "segment-starts",
                "selection",
                10,
                (1, 0, 0, 0, 1, 0, 0, 0, 0, 0),
            ),
        ),
        rotation_catalog=RotationCatalog(((1, 1), (2, 2))),
        nodes=(
            MultiplyCiphertexts("product", "value-page", "query-page"),
            Relinearize("relinearized", "product"),
            Rotate("shift-1", "relinearized", 1, 1),
            AddCiphertexts("sum-2", "relinearized", "shift-1"),
            Rotate("shift-2", "sum-2", 2, 2),
            AddCiphertexts("sum-4", "sum-2", "shift-2"),
            MultiplyPlaintextMask("selected", "sum-4", "segment-starts"),
            AddF1MMask("masked", "selected", "blind", "opaque-zero-sum"),
            ReturnResult("page-result", "masked"),
        ),
        result_ids=("page-result",),
    )
    return CloudExecutionPlan(
        program=program,
        binding=ExecutionBinding(
            format=EXECUTION_BINDING_FORMAT,
            version_id="v1",
            output_plan_digest="0" * 64,
            cloud_program_digest=cloud_program_digest(program),
        ),
    )


def _plan_for_public_page_shapes(
    output_plan_digest: str,
    page_shapes,
) -> CloudExecutionPlan:
    assert page_shapes
    first = page_shapes[0]
    program = build_fixed_stride_cloud_program(
        page_count=len(page_shapes),
        effective_slots=first.slot_count,
        segment_width=first.segment_width,
    )
    return CloudExecutionPlan(
        program=program,
        binding=ExecutionBinding(
            format=EXECUTION_BINDING_FORMAT,
            version_id="v2",
            output_plan_digest=output_plan_digest,
            cloud_program_digest=cloud_program_digest(program),
        ),
    )


def test_direct_spmv_uses_global_columns_and_modular_arithmetic() -> None:
    matrix = {
        (0, 1): 3,
        (0, 11): -2,
        (1, 7): 5,
        (2, 10): 4,
    }
    vector = (0, 6, 0, 0, 0, 0, 0, 9, 0, 0, 8, 7)

    assert direct_spmv(matrix, vector, rows=3, cols=12, modulus=97) == (
        4,
        45,
        32,
    )


def test_execute_cloud_plan_follows_exact_fixed_stride_dag_with_tail() -> None:
    results = execute_cloud_plan(
        _fixed_stride_plan(),
        ciphertext_inputs={
            "value-page": (2, 3, 0, 0, 5, 7, 11, 0, 0, 0),
            "query-page": (6, 4, 0, 0, 9, 2, 3, 0, 0, 0),
            "blind": (5, 0, 0, 0, 7, 0, 0, 0, 0, 0),
        },
        plaintext_masks={"segment-starts": (1, 0, 0, 0, 1, 0, 0, 0, 0, 0)},
        modulus=97,
    )

    assert results == {"page-result": (29, 0, 0, 0, 2, 0, 0, 0, 0, 0)}


def test_rotate_executes_the_verified_openfhe_index_not_the_logical_label() -> None:
    program = CloudProgram(
        format=CLOUD_PROGRAM_FORMAT,
        slot_count=4,
        ciphertext_inputs=(
            CiphertextInput("values", "value", 4),
            CiphertextInput("query", "query", 4),
            CiphertextInput("f1m", "f1m-mask", 4),
        ),
        plaintext_masks=(PlaintextMask("selection", "selection", 4, (1, 1, 1, 1)),),
        rotation_catalog=RotationCatalog(((1, 3),)),
        nodes=(
            MultiplyCiphertexts("product", "values", "query"),
            Relinearize("relinearized", "product"),
            Rotate("rotated", "relinearized", 1, 3),
            MultiplyPlaintextMask("selected", "rotated", "selection"),
            AddF1MMask("masked", "selected", "f1m", "opaque-zero-sum"),
            ReturnResult("result", "masked"),
        ),
        result_ids=("result",),
    )
    plan = CloudExecutionPlan(
        program=program,
        binding=ExecutionBinding(
            format=EXECUTION_BINDING_FORMAT,
            version_id="v-index-counterexample",
            output_plan_digest="3" * 64,
            cloud_program_digest=cloud_program_digest(program),
        ),
    )

    results = execute_cloud_plan(
        plan,
        ciphertext_inputs={
            "values": (1, 2, 3, 4),
            "query": (1, 1, 1, 1),
            "f1m": (0, 0, 0, 0),
        },
        plaintext_masks={"selection": (1, 1, 1, 1)},
        modulus=17,
    )

    assert results == {"result": (4, 1, 2, 3)}


def test_single_effective_row_executor_rejects_an_out_of_range_rotation_index() -> None:
    plan = _fixed_stride_plan()
    program = replace(
        plan.program,
        rotation_catalog=RotationCatalog(((1, 10), (2, 2))),
        nodes=tuple(
            replace(node, openfhe_index=10)
            if isinstance(node, Rotate) and node.logical_shift == 1
            else node
            for node in plan.program.nodes
        ),
    )
    out_of_range = replace(
        plan,
        program=program,
        binding=replace(
            plan.binding,
            cloud_program_digest=cloud_program_digest(program),
        ),
    )

    with pytest.raises(ValueError, match="single-effective-row.*range"):
        execute_cloud_plan(
            out_of_range,
            ciphertext_inputs={
                "value-page": (0,) * 10,
                "query-page": (0,) * 10,
                "blind": (0,) * 10,
            },
            plaintext_masks={"segment-starts": (1, 0, 0, 0, 1, 0, 0, 0, 0, 0)},
            modulus=17,
        )


def test_execute_cloud_plan_requires_the_exact_declared_public_operands() -> None:
    with pytest.raises(ValueError, match="exactly match"):
        execute_cloud_plan(
            _fixed_stride_plan(),
            ciphertext_inputs={
                "value-page": (0,) * 10,
                "query-page": (0,) * 10,
            },
            plaintext_masks={"segment-starts": (0,) * 10},
            modulus=17,
        )


def test_execute_cloud_plan_rejects_plaintext_mask_bit_replacement() -> None:
    with pytest.raises(ValueError, match="committed plaintext mask"):
        execute_cloud_plan(
            _fixed_stride_plan(),
            ciphertext_inputs={
                "value-page": (0,) * 10,
                "query-page": (0,) * 10,
                "blind": (0,) * 10,
            },
            plaintext_masks={"segment-starts": (1, 0, 0, 0, 0, 0, 0, 0, 0, 0)},
            modulus=17,
        )


def test_plaintext_executor_matches_direct_spmv_for_versioned_multi_page_delta() -> None:
    state = initialize_segmented_delta(
        rows=3,
        cols=12,
        effective_slots=4,
        segment_width=2,
        matrix_value_bound=20,
        version_id="v0",
    )
    first = advance_segmented_delta(
        state,
        delta_updates=(),
        overflow_entries=(
            StrongEntry(0, 7, 2),
            StrongEntry(0, 8, 3),
            StrongEntry(0, 11, 5),
            StrongEntry(1, 9, 4),
        ),
        version_id="v1",
    )
    second = advance_segmented_delta(
        first.state,
        delta_updates=(NetUpdate(0, 7, 2, -2), NetUpdate(0, 8, 3, 0)),
        overflow_entries=(StrongEntry(0, 10, 6),),
        version_id="v2",
    )
    page_shapes = cloud_page_shapes(second.state)
    assert len(page_shapes) == 2
    assert second.new_segment_count == 0
    assert second.ci_patch_entries == 1

    vector = tuple(range(1, 13))
    metadata = client_b_page_metadata(second.state)
    assert metadata[0].global_column_indices == (7, 10, 11, -1)
    assert metadata[1].global_column_indices == (9, -1, -1, -1)
    page_values = [[0] * 4 for _ in metadata]
    for segment in second.state.segments:
        for offset, entry in enumerate(segment.entries):
            if entry is not None:
                page_values[segment.page_ordinal][segment.slot_start + offset] = entry.value
    page_queries = {
        f"query-{page}": tuple(
            vector[global_col] if global_col >= 0 else 0
            for global_col in page_metadata.global_column_indices
        )
        for page, page_metadata in enumerate(metadata)
    }

    base_share = OutputShare("base", "rows", ((0, 0), (2, 2)))
    output_plan = OutputPlan(
        logical_output_size=3,
        slot_count=4,
        shares=(base_share, *post_aggregation_output_shares(second.state)),
    )
    analysis = analyze_output_plan(output_plan)
    assert analysis.client_modular_additions == 2
    executed = execute_cloud_plan(
        _plan_for_public_page_shapes(analysis.output_plan_digest, page_shapes),
        ciphertext_inputs={
            "ct-value-000000": tuple(page_values[0]),
            "ct-query-000000": page_queries["query-0"],
            "ct-f1m-000000": (9, 0, 75, 0),
            "ct-value-000001": tuple(page_values[1]),
            "ct-query-000001": page_queries["query-1"],
            "ct-f1m-000001": (0, 0, 0, 0),
        },
        plaintext_masks={
            "pt-selection-000000": (1, 0, 1, 0),
            "pt-selection-000001": (1, 0, 1, 0),
        },
        modulus=97,
    )
    returned = {
        ("base", "rows"): (25, 0, 28, 0),
        (STRONG_COMPONENT_ID, "page-000000"): executed["page-000000"],
        (STRONG_COMPONENT_ID, "page-000001"): executed["page-000001"],
    }
    reconstructed = reconstruct_output(output_plan, returned, modulus=97)
    expected = direct_spmv(
        {
            (0, 1): 6,
            (2, 3): 7,
            **decode_segmented_delta(second.state),
        },
        vector,
        rows=3,
        cols=12,
        modulus=97,
    )

    assert reconstructed == expected == (25, 40, 28)


def test_reconstruction_aligns_returned_pages_by_output_share_identity() -> None:
    plan = OutputPlan(
        logical_output_size=3,
        slot_count=4,
        shares=(
            OutputShare("base", "rows", ((0, 0), (2, 1))),
            OutputShare("strong-packed-coo-delta", "page-000001", ((0, 0), (2, 2))),
            OutputShare("strong-packed-coo-delta", "page-000000", ((1, 0),)),
        ),
    )
    returned = {
        ("strong-packed-coo-delta", "page-000000"): (0, 7, 0, 0),
        ("base", "rows"): (11, 0, 13, 0),
        ("strong-packed-coo-delta", "page-000001"): (17, 0, 19, 0),
    }

    assert reconstruct_output(plan, returned, modulus=23) == (12, 13, 19)


def test_reconstruction_fails_closed_on_missing_or_unbound_returned_share() -> None:
    plan = OutputPlan(
        logical_output_size=1,
        slot_count=2,
        shares=(OutputShare("delta", "page", ((0, 0),)),),
    )

    with pytest.raises(ValueError, match="exactly match"):
        reconstruct_output(plan, {}, modulus=17)
    with pytest.raises(ValueError, match="exactly match"):
        reconstruct_output(
            plan,
            {
                ("delta", "page"): (1, 0),
                ("other", "page"): (0, 0),
            },
            modulus=17,
        )
