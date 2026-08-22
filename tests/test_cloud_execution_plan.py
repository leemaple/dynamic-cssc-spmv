from __future__ import annotations

import inspect
from dataclasses import FrozenInstanceError, replace

import pytest

from dynamic_cssc.cloud_execution_plan import (
    CLOUD_PROGRAM_FORMAT,
    AddCiphertexts,
    AddF1MMask,
    CiphertextInput,
    CloudExecutionPlanError,
    CloudProgram,
    MultiplyCiphertexts,
    MultiplyPlaintextMask,
    PlaintextMask,
    Relinearize,
    ReturnResult,
    Rotate,
    RotationCatalog,
    build_fixed_stride_cloud_program,
    canonical_cloud_program_payload,
    validate_cloud_program,
    validate_fixed_stride_cloud_program,
)


def _fixed_stride_program() -> CloudProgram:
    return CloudProgram(
        format=CLOUD_PROGRAM_FORMAT,
        slot_count=8,
        ciphertext_inputs=(
            CiphertextInput("value-page", "value", 8),
            CiphertextInput("query-page", "query", 8),
            CiphertextInput("blind", "f1m-mask", 8),
        ),
        plaintext_masks=(
            PlaintextMask("segment-starts", "selection", 8, (1, 0, 0, 0, 1, 0, 0, 0)),
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
            ReturnResult("share-0", "masked"),
        ),
        result_ids=("share-0",),
    )


def test_fixed_stride_program_is_a_frozen_typed_ssa_dag() -> None:
    program = _fixed_stride_program()

    validate_cloud_program(program)

    assert canonical_cloud_program_payload(program)["nodes"][2] == {
        "ciphertext_id": "relinearized",
        "logical_shift": 1,
        "openfhe_index": 1,
        "op": "rotate",
        "result_id": "shift-1",
    }
    assert canonical_cloud_program_payload(program)["plaintext_masks"] == [
        {
            "length": 8,
            "mask_id": "segment-starts",
            "role": "selection",
            "values": [1, 0, 0, 0, 1, 0, 0, 0],
        }
    ]
    with pytest.raises(FrozenInstanceError):
        program.slot_count = 16  # type: ignore[misc]


def test_declared_operands_must_be_consumed_by_the_returned_graph() -> None:
    program = _fixed_stride_program()
    with_unused_mask = replace(
        program,
        plaintext_masks=(
            *program.plaintext_masks,
            PlaintextMask("unused-private-shape", "selection", 8, (1, 0, 0, 0, 1, 0, 0, 0)),
        ),
    )

    with pytest.raises(CloudExecutionPlanError, match="operand.*returned result"):
        validate_cloud_program(with_unused_mask)


def test_ciphertext_multiplication_requires_one_direct_relinearization() -> None:
    program = _fixed_stride_program()
    without_relinearization = replace(
        program,
        nodes=(
            program.nodes[0],
            Rotate("shift-1", "product", 1, 1),
            AddCiphertexts("sum-2", "product", "shift-1"),
            Rotate("shift-2", "sum-2", 2, 2),
            AddCiphertexts("sum-4", "sum-2", "shift-2"),
            MultiplyPlaintextMask("selected", "sum-4", "segment-starts"),
            AddF1MMask("masked", "selected", "blind", "opaque-zero-sum"),
            ReturnResult("share-0", "masked"),
        ),
    )

    with pytest.raises(CloudExecutionPlanError, match="direct Relinearize"):
        validate_cloud_program(without_relinearization)


def test_relinearize_cannot_consume_an_add_or_other_computed_result() -> None:
    program = _fixed_stride_program()
    spurious_relinearization = Relinearize("fake-relinearized", "relinearized")
    shifted = replace(program.nodes[2], ciphertext_id="fake-relinearized")

    with pytest.raises(
        CloudExecutionPlanError,
        match="Relinearize input must be a direct MultiplyCiphertexts result",
    ):
        validate_cloud_program(
            replace(
                program,
                nodes=(
                    *program.nodes[:2],
                    spurious_relinearization,
                    shifted,
                    *program.nodes[3:],
                ),
            )
        )


def test_ssa_references_must_follow_definition_order() -> None:
    program = _fixed_stride_program()
    forward_reference = replace(
        program.nodes[2],
        ciphertext_id="sum-2",
    )

    with pytest.raises(CloudExecutionPlanError, match="previously defined"):
        validate_cloud_program(
            replace(program, nodes=(*program.nodes[:2], forward_reference, *program.nodes[3:]))
        )


def test_ssa_identifiers_cannot_be_redefined() -> None:
    program = _fixed_stride_program()
    duplicate_definition = replace(program.nodes[2], result_id="relinearized")

    with pytest.raises(CloudExecutionPlanError, match="identifiers must be unique"):
        validate_cloud_program(
            replace(
                program,
                nodes=(*program.nodes[:2], duplicate_definition, *program.nodes[3:]),
            )
        )


def test_multiply_ciphertexts_requires_value_and_query_roles() -> None:
    program = _fixed_stride_program()
    wrong_role = replace(program.ciphertext_inputs[1], role="value")

    with pytest.raises(CloudExecutionPlanError, match="value and query roles"):
        validate_cloud_program(
            replace(
                program,
                ciphertext_inputs=(
                    program.ciphertext_inputs[0],
                    wrong_role,
                    *program.ciphertext_inputs[2:],
                ),
            )
        )


def test_value_and_query_inputs_cannot_bypass_ciphertext_multiplication() -> None:
    program = _fixed_stride_program()
    bypassed_multiply = AddCiphertexts("combined", "value-page", "query-page")

    with pytest.raises(CloudExecutionPlanError, match="value and query operands.*Multiply"):
        validate_cloud_program(
            replace(
                program,
                nodes=(
                    bypassed_multiply,
                    MultiplyPlaintextMask("selected", "combined", "segment-starts"),
                    AddF1MMask("masked", "selected", "blind", "opaque-zero-sum"),
                    ReturnResult("share-0", "masked"),
                ),
            )
        )


def test_operand_lengths_must_equal_the_program_slot_count() -> None:
    program = _fixed_stride_program()
    short_mask = replace(program.plaintext_masks[0], length=4)

    with pytest.raises(CloudExecutionPlanError, match="length must equal slot_count"):
        validate_cloud_program(replace(program, plaintext_masks=(short_mask,)))


@pytest.mark.parametrize(
    "values",
    (
        (1, 0, 0),
        (1, 0, 2, 0, 1, 0, 0, 0),
        (True, 0, 0, 0, 1, 0, 0, 0),
        [1, 0, 0, 0, 1, 0, 0, 0],
    ),
)
def test_selection_mask_values_are_exact_strict_binary_tuples(values: object) -> None:
    program = _fixed_stride_program()
    invalid_mask = replace(program.plaintext_masks[0], values=values)

    with pytest.raises(CloudExecutionPlanError, match="plaintext mask values|strict 0/1"):
        validate_cloud_program(replace(program, plaintext_masks=(invalid_mask,)))


def test_rotate_uses_the_catalogued_openfhe_index_without_inference() -> None:
    program = _fixed_stride_program()
    inferred_modular_index = replace(program.nodes[2], openfhe_index=-7)

    with pytest.raises(CloudExecutionPlanError, match="exact.*catalog entry"):
        validate_cloud_program(
            replace(
                program,
                nodes=(*program.nodes[:2], inferred_modular_index, *program.nodes[3:]),
            )
        )


def test_result_ids_exactly_match_return_nodes_in_program_order() -> None:
    program = _fixed_stride_program()

    with pytest.raises(CloudExecutionPlanError, match="exactly match ReturnResult"):
        validate_cloud_program(replace(program, result_ids=("other-result",)))


def test_return_result_identifier_cannot_collide_with_an_operand_or_ssa_id() -> None:
    program = _fixed_stride_program()
    colliding_return = replace(program.nodes[-1], result_id="value-page")

    with pytest.raises(CloudExecutionPlanError, match="identifiers must be unique"):
        validate_cloud_program(
            replace(
                program,
                nodes=(*program.nodes[:-1], colliding_return),
                result_ids=("value-page",),
            )
        )


def test_builder_emits_one_fixed_stride_pipeline_per_public_page() -> None:
    program = build_fixed_stride_cloud_program(
        page_count=2,
        effective_slots=10,
        segment_width=4,
    )

    validate_cloud_program(program)

    assert program.slot_count == 10
    assert program.result_ids == ("page-000000", "page-000001")
    assert program.rotation_catalog == RotationCatalog(((1, 1), (2, 2)))
    assert tuple(mask.values for mask in program.plaintext_masks) == (
        (1, 0, 0, 0, 1, 0, 0, 0, 0, 0),
        (1, 0, 0, 0, 1, 0, 0, 0, 0, 0),
    )
    assert (
        tuple(type(node) for node in program.nodes)
        == (
            MultiplyCiphertexts,
            Relinearize,
            Rotate,
            AddCiphertexts,
            Rotate,
            AddCiphertexts,
            MultiplyPlaintextMask,
            AddF1MMask,
            ReturnResult,
        )
        * 2
    )


def test_builder_accepts_only_the_uniform_public_page_shape() -> None:
    assert tuple(inspect.signature(build_fixed_stride_cloud_program).parameters) == (
        "page_count",
        "effective_slots",
        "segment_width",
    )


@pytest.mark.parametrize(
    "malicious_argument",
    (
        {"page_ids": ("logical-row-7",)},
        {"selection_values": (0,) * 8},
        {"result_ids": ("private-coordinate-7",)},
    ),
)
def test_builder_does_not_accept_private_ids_or_caller_supplied_masks(
    malicious_argument: dict[str, object],
) -> None:
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        build_fixed_stride_cloud_program(
            page_count=1,
            effective_slots=8,
            segment_width=2,
            **malicious_argument,
        )


@pytest.mark.parametrize(
    ("page_count", "effective_slots", "segment_width"),
    (
        (True, 8, 2),
        (-1, 8, 2),
        (1, True, 2),
        (1, 8, 1),
        (1, 8, 3),
        (1, 8, 16),
    ),
)
def test_builder_rejects_non_public_or_invalid_page_shapes(
    page_count: object,
    effective_slots: object,
    segment_width: object,
) -> None:
    with pytest.raises(CloudExecutionPlanError):
        build_fixed_stride_cloud_program(
            page_count=page_count,  # type: ignore[arg-type]
            effective_slots=effective_slots,  # type: ignore[arg-type]
            segment_width=segment_width,  # type: ignore[arg-type]
        )


def test_production_validator_rejects_a_generic_ir_with_private_semantic_ids() -> None:
    program = build_fixed_stride_cloud_program(
        page_count=1,
        effective_slots=8,
        segment_width=2,
    )
    renamed_input = replace(
        program.ciphertext_inputs[0],
        ciphertext_id="logical-row-7-values",
    )
    renamed_nodes = tuple(
        replace(node, left_id="logical-row-7-values")
        if isinstance(node, MultiplyCiphertexts)
        else node
        for node in program.nodes
    )
    generic_ir = replace(
        program,
        ciphertext_inputs=(renamed_input, *program.ciphertext_inputs[1:]),
        nodes=renamed_nodes,
    )

    validate_cloud_program(generic_ir)
    validate_fixed_stride_cloud_program(
        program,
        page_count=1,
        effective_slots=8,
        segment_width=2,
    )
    with pytest.raises(CloudExecutionPlanError, match="fixed-stride canonical program"):
        validate_fixed_stride_cloud_program(
            generic_ir,
            page_count=1,
            effective_slots=8,
            segment_width=2,
        )
