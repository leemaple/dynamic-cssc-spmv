from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import replace

import pytest

from dynamic_cssc.cloud_execution_plan import (
    AddCiphertexts,
    AddF1MMask,
    CiphertextInput,
    ReturnResult,
    Rotate,
    canonical_cloud_visible_bytes,
    cloud_program_digest,
    validate_cloud_execution_plan,
)
from dynamic_cssc.cssc import publish_component
from dynamic_cssc.plaintext_oracle import (
    direct_spmv,
    execute_cloud_plan,
    execute_compiled_query,
    reconstruct_output,
)
from dynamic_cssc.query_compiler import (
    CLIENT_LANE_COMPONENT_ID,
    QueryCompilerError,
    compile_query,
    validate_compiled_query,
)
from dynamic_cssc.strategy_state import PackedCOOEntry, PackedCOOSegment
from dynamic_cssc.strong_execution import compile_strong_execution
from dynamic_cssc.strong_packed_coo import (
    StrongEntry,
    advance_segmented_delta,
    initialize_segmented_delta,
)


class _LiarPolicy(str):
    def __eq__(self, other: object) -> bool:
        return super().__eq__(other)

    def __ne__(self, other: object) -> bool:
        return False


class _NoComparePolicy(str):
    def __eq__(self, other: object) -> bool:
        raise AssertionError("policy subclass comparison was dispatched")

    def __ne__(self, other: object) -> bool:
        raise AssertionError("policy subclass comparison was dispatched")


class _NoAccessMapping(Mapping[str, tuple[int, ...]]):
    def __getitem__(self, key: str) -> tuple[int, ...]:
        raise AssertionError("operand mapping was accessed")

    def __iter__(self) -> Iterator[str]:
        raise AssertionError("operand mapping was accessed")

    def __len__(self) -> int:
        raise AssertionError("operand mapping was accessed")


def _single_component():
    return publish_component(
        {(0, 0): 2},
        rows=1,
        cols=1,
        effective_slots=2,
        version_id="v1",
        component_prefix="base",
    )


def _execute(compiled, vector: tuple[int, ...], modulus: int = 97) -> tuple[int, ...]:
    ciphertexts = {}
    for spec in compiled.operand_specs:
        ciphertexts[spec.value_ciphertext_id] = spec.values
        ciphertexts[spec.query_ciphertext_id] = tuple(
            vector[column] if column >= 0 else 0 for column in spec.global_column_indices
        )
    ciphertexts.update(
        {
            route.f1m_ciphertext_id: (0,) * compiled.output_plan.slot_count
            for route in compiled.result_routes
            if route.f1m_ciphertext_id is not None
        }
    )
    returned = execute_compiled_query(
        compiled,
        expected_f1m_policy=compiled.f1m_policy,
        ciphertext_inputs=ciphertexts,
        plaintext_masks={
            mask.mask_id: mask.values for mask in compiled.cloud_plan.program.plaintext_masks
        },
        modulus=modulus,
    )
    return reconstruct_output(
        compiled.output_plan,
        {route.output_share_id: returned[route.result_id] for route in compiled.result_routes},
        modulus=modulus,
    )


@pytest.mark.parametrize(
    "policy",
    (
        pytest.param(_LiarPolicy("overlap-only"), id="str-subclass"),
        pytest.param("unsupported", id="out-of-domain"),
        pytest.param(None, id="non-string"),
    ),
)
def test_compile_query_rejects_a_noncanonical_policy(policy: object) -> None:
    with pytest.raises(QueryCompilerError, match="f1m_policy"):
        compile_query((_single_component(),), f1m_policy=policy)


@pytest.mark.parametrize(
    "expected_policy",
    (
        pytest.param(_LiarPolicy("overlap-only"), id="str-subclass"),
        pytest.param("unsupported", id="out-of-domain"),
        pytest.param(None, id="non-string"),
    ),
)
def test_compiled_execution_rejects_a_noncanonical_expected_policy_before_operands(
    expected_policy: object,
) -> None:
    compiled = compile_query((_single_component(),))
    operands = _NoAccessMapping()

    with pytest.raises(QueryCompilerError, match="expected_f1m_policy"):
        execute_compiled_query(
            compiled,
            expected_f1m_policy=expected_policy,
            ciphertext_inputs=operands,
            plaintext_masks=operands,
            modulus=97,
        )


@pytest.mark.parametrize(
    "forged_policy",
    (
        pytest.param(_LiarPolicy("overlap-only"), id="liar-str-subclass"),
        pytest.param(_NoComparePolicy("overlap-only"), id="no-compare-str-subclass"),
        pytest.param("unsupported", id="out-of-domain"),
        pytest.param(None, id="non-string"),
    ),
)
def test_forged_compiled_policies_fail_closed_before_comparison_or_operands(
    forged_policy: object,
) -> None:
    forged = replace(
        compile_query((_single_component(),)),
        f1m_policy=forged_policy,
    )
    operands = _NoAccessMapping()

    with pytest.raises(QueryCompilerError, match="f1m_policy"):
        validate_compiled_query(forged)
    with pytest.raises(QueryCompilerError, match="f1m_policy"):
        execute_compiled_query(
            forged,
            expected_f1m_policy="uniform-random-or-zero",
            ciphertext_inputs=operands,
            plaintext_masks=operands,
            modulus=97,
        )


@pytest.mark.parametrize("policy", ("overlap-only", "uniform-random-or-zero"))
def test_exact_builtin_policies_still_compile_validate_and_execute(policy: str) -> None:
    compiled = compile_query((_single_component(),), f1m_policy=policy)

    validate_compiled_query(compiled)
    assert type(compiled.f1m_policy) is str
    assert _execute(compiled, (5,)) == (10,)


def test_compiled_execution_rejects_a_non_compilation_before_attributes_or_operands() -> None:
    operands = _NoAccessMapping()

    with pytest.raises(QueryCompilerError, match="compiled must be a CompiledQuery"):
        execute_compiled_query(
            None,
            expected_f1m_policy="overlap-only",
            ciphertext_inputs=operands,
            plaintext_masks=operands,
            modulus=97,
        )


def test_default_overlap_only_compilation_executes_a_disjoint_result() -> None:
    component = publish_component(
        {(0, 0): 2},
        rows=1,
        cols=1,
        effective_slots=2,
        version_id="v1",
        component_prefix="base",
    )
    compiled = compile_query((component,))

    assert compiled.f1m_policy == "overlap-only"
    assert compiled.cloud_counts.add_f1m_masks == 0
    assert _execute(compiled, (5,)) == (10,)

    with pytest.raises(ValueError, match="AddF1MMask"):
        execute_cloud_plan(
            compiled.cloud_plan,
            ciphertext_inputs={},
            plaintext_masks={},
            modulus=97,
        )


def test_overlap_only_execution_applies_random_zero_sum_masks_to_both_shares() -> None:
    left = publish_component(
        {(0, 0): 2},
        rows=1,
        cols=2,
        effective_slots=2,
        version_id="v1",
        component_prefix="left",
    )
    right = publish_component(
        {(0, 1): 3},
        rows=1,
        cols=2,
        effective_slots=2,
        version_id="v1",
        component_prefix="right",
    )
    compiled = compile_query((left, right))
    ciphertexts = {}
    for spec in compiled.operand_specs:
        ciphertexts[spec.value_ciphertext_id] = spec.values
        ciphertexts[spec.query_ciphertext_id] = tuple(
            (5, 7)[column] if column >= 0 else 0 for column in spec.global_column_indices
        )
    ciphertexts[compiled.result_routes[0].f1m_ciphertext_id] = (9, 0)
    ciphertexts[compiled.result_routes[1].f1m_ciphertext_id] = (88, 0)

    returned = execute_compiled_query(
        compiled,
        expected_f1m_policy="overlap-only",
        ciphertext_inputs=ciphertexts,
        plaintext_masks={
            mask.mask_id: mask.values for mask in compiled.cloud_plan.program.plaintext_masks
        },
        modulus=97,
    )

    assert tuple(returned[route.result_id][0] for route in compiled.result_routes) == (19, 12)
    assert reconstruct_output(
        compiled.output_plan,
        {route.output_share_id: returned[route.result_id] for route in compiled.result_routes},
        modulus=97,
    ) == (31,)


def test_expected_uniform_policy_rejects_an_all_overlap_inverse_policy_relabel() -> None:
    left = publish_component(
        {(0, 0): 2},
        rows=1,
        cols=2,
        effective_slots=2,
        version_id="v1",
        component_prefix="left",
    )
    right = publish_component(
        {(0, 1): 3},
        rows=1,
        cols=2,
        effective_slots=2,
        version_id="v1",
        component_prefix="right",
    )
    original = compile_query(
        (left, right),
        f1m_policy="uniform-random-or-zero",
    )
    relabeled = replace(original, f1m_policy="overlap-only")
    validate_compiled_query(relabeled)
    ciphertexts = {}
    for spec in original.operand_specs:
        ciphertexts[spec.value_ciphertext_id] = spec.values
        ciphertexts[spec.query_ciphertext_id] = tuple(
            (5, 7)[column] if column >= 0 else 0 for column in spec.global_column_indices
        )
    ciphertexts.update(
        {
            route.f1m_ciphertext_id: (0, 0)
            for route in original.result_routes
            if route.f1m_ciphertext_id is not None
        }
    )
    plaintext_masks = {
        mask.mask_id: mask.values for mask in original.cloud_plan.program.plaintext_masks
    }

    with pytest.raises(QueryCompilerError, match="expected_f1m_policy"):
        execute_compiled_query(
            relabeled,
            expected_f1m_policy="uniform-random-or-zero",
            ciphertext_inputs=ciphertexts,
            plaintext_masks=plaintext_masks,
            modulus=97,
        )

    returned = execute_compiled_query(
        original,
        expected_f1m_policy="uniform-random-or-zero",
        ciphertext_inputs=ciphertexts,
        plaintext_masks=plaintext_masks,
        modulus=97,
    )
    assert tuple(returned[route.result_id][0] for route in original.result_routes) == (10, 21)


def test_compiled_execution_rejects_tampered_policy_and_routes_before_operands() -> None:
    component = publish_component(
        {(0, 0): 2},
        rows=1,
        cols=1,
        effective_slots=2,
        version_id="v1",
        component_prefix="base",
    )
    compiled = compile_query((component,))
    variants = (
        replace(compiled, f1m_policy="uniform-random-or-zero"),
        replace(
            compiled,
            result_routes=(replace(compiled.result_routes[0], output_block_id="unbound-block"),),
        ),
    )

    for tampered in variants:
        with pytest.raises(QueryCompilerError):
            execute_compiled_query(
                tampered,
                expected_f1m_policy="overlap-only",
                ciphertext_inputs={},
                plaintext_masks={},
                modulus=97,
            )


def test_width_three_uses_corrected_stored_power_prefix_schedule() -> None:
    component = publish_component(
        {(0, 0): 2, (0, 1): 3, (0, 2): 5},
        rows=1,
        cols=3,
        effective_slots=8,
        version_id="v1",
        component_prefix="base",
    )

    compiled = compile_query(
        (component,),
        f1m_policy="uniform-random-or-zero",
    )

    rotations = tuple(
        node for node in compiled.cloud_plan.program.nodes if isinstance(node, Rotate)
    )
    additions = tuple(
        node for node in compiled.cloud_plan.program.nodes if isinstance(node, AddCiphertexts)
    )
    assert tuple(node.logical_shift for node in rotations) == (1, 2)
    assert rotations[0].ciphertext_id == rotations[1].ciphertext_id
    assert additions[0].left_id == rotations[0].ciphertext_id
    assert additions[1].left_id == additions[0].result_id
    assert additions[1].right_id == rotations[1].result_id


def test_width_seven_uses_the_exact_corrected_dependencies_and_direct_shifts() -> None:
    component = publish_component(
        {(0, column): column + 1 for column in range(7)},
        rows=1,
        cols=7,
        effective_slots=8,
        version_id="v1",
        component_prefix="base",
    )

    compiled = compile_query((component,), f1m_policy="uniform-random-or-zero")

    rotations = tuple(
        node for node in compiled.cloud_plan.program.nodes if isinstance(node, Rotate)
    )
    additions = tuple(
        node for node in compiled.cloud_plan.program.nodes if isinstance(node, AddCiphertexts)
    )
    relinearized_id = compiled.cloud_plan.program.nodes[1].result_id
    assert tuple(node.logical_shift for node in rotations) == (1, 2, 4, 6)
    assert tuple(node.ciphertext_id for node in rotations) == (
        relinearized_id,
        additions[0].result_id,
        additions[0].result_id,
        relinearized_id,
    )
    assert compiled.cloud_plan.program.rotation_catalog.entries == (
        (1, 1),
        (2, 2),
        (4, 4),
        (6, 6),
    )
    assert _execute(compiled, (1, 2, 3, 4, 5, 6, 7)) == (43,)


@pytest.mark.parametrize("width", range(1, 9))
def test_small_chunk_widths_match_an_independent_direct_spmv_oracle(width: int) -> None:
    state = {(0, column): (-1) ** column * (column + 1) for column in range(width)}
    component = publish_component(
        state,
        rows=1,
        cols=8,
        effective_slots=8,
        version_id="v1",
        component_prefix="base",
    )
    vector = tuple(range(2, 10))

    compiled = compile_query((component,), f1m_policy="uniform-random-or-zero")

    assert _execute(compiled, vector) == direct_spmv(state, vector, rows=1, cols=8, modulus=97)
    expected_rotations = width.bit_length() - 1 + width.bit_count() - 1 if width > 1 else 0
    assert compiled.cloud_counts.rotations == expected_rotations


def test_width_one_is_identity_and_selects_only_when_height_is_not_all_slots() -> None:
    full_height = publish_component(
        {(row, 0): row + 1 for row in range(4)},
        rows=4,
        cols=1,
        effective_slots=4,
        version_id="v1",
        component_prefix="full",
    )
    short_height = publish_component(
        {(0, 0): 1},
        rows=1,
        cols=1,
        effective_slots=4,
        version_id="v1",
        component_prefix="short",
    )

    full = compile_query((full_height,), f1m_policy="uniform-random-or-zero")
    short = compile_query((short_height,), f1m_policy="uniform-random-or-zero")

    assert full.cloud_counts.rotations == short.cloud_counts.rotations == 0
    assert full.cloud_counts.multiply_plaintext_masks == 0
    assert short.cloud_counts.multiply_plaintext_masks == 1
    assert _execute(full, (3,)) == (3, 6, 9, 12)
    assert _execute(short, (3,)) == (3,)


def test_two_components_keep_cloud_results_separate_and_merge_at_reconstruction() -> None:
    left = publish_component(
        {(0, 0): 2},
        rows=1,
        cols=2,
        effective_slots=4,
        version_id="v1",
        component_prefix="z-left",
    )
    right = publish_component(
        {(0, 1): 3},
        rows=1,
        cols=2,
        effective_slots=4,
        version_id="v1",
        component_prefix="a-right",
    )

    compiled = compile_query((left, right), f1m_policy="overlap-only")

    assert tuple(component.component_id for component in compiled.components) == (
        "a-right",
        "z-left",
    )
    assert compiled.cloud_plan.program.result_ids == ("result-000000", "result-000001")
    assert compiled.cloud_counts.add_ciphertexts == 0
    assert compiled.cloud_counts.add_f1m_masks == 2
    assert _execute(compiled, (5, 7)) == (31,)


def test_chunks_merge_only_within_their_output_block_and_horizontal_blocks_stay_separate() -> None:
    multi_chunk = publish_component(
        {(0, column): 1 for column in range(6)},
        rows=1,
        cols=6,
        effective_slots=4,
        version_id="v1",
        component_prefix="wide",
    )
    horizontal = publish_component(
        {(0, 0): 1, (3, 0): 2},
        rows=4,
        cols=1,
        effective_slots=4,
        partition_rows=2,
        version_id="v1",
        component_prefix="horizontal",
    )

    chunks = compile_query((multi_chunk,), f1m_policy="uniform-random-or-zero")
    blocks = compile_query((horizontal,), f1m_policy="uniform-random-or-zero")

    assert len(chunks.operand_specs) == 2
    assert len(chunks.result_routes) == 1
    assert {spec.result_id for spec in chunks.operand_specs} == {"result-000000"}
    assert _execute(chunks, (1, 2, 3, 4, 5, 6)) == (21,)
    assert len(blocks.result_routes) == 2
    assert tuple(route.output_block_id for route in blocks.result_routes) == (
        "horizontal-h000000",
        "horizontal-h000001",
    )
    assert _execute(blocks, (3,)) == (3, 0, 0, 6)


def test_client_lane_segments_use_one_unaggregated_pipeline_per_active_segment() -> None:
    base = publish_component(
        {},
        rows=3,
        cols=4,
        effective_slots=4,
        version_id="v1",
        component_prefix="base",
    )
    segments = (
        PackedCOOSegment(
            "segment-000001",
            "v1",
            2,
            (PackedCOOEntry((0, 1), 2), PackedCOOEntry((2, 3), 5)),
        ),
        PackedCOOSegment("segment-000000", "v1", 2, (None, None)),
    )

    compiled = compile_query(
        (base,),
        client_lane_segments=segments,
        f1m_policy="uniform-random-or-zero",
    )

    assert len(compiled.operand_specs) == 1
    assert compiled.operand_specs[0].source_kind == "client-lane-segment"
    assert compiled.cloud_counts.multiply_ciphertexts == 1
    assert compiled.cloud_counts.relinearizations == 1
    assert compiled.cloud_counts.rotations == 0
    assert compiled.cloud_counts.multiply_plaintext_masks == 0
    assert compiled.cloud_counts.returned_ciphertexts == 1
    assert compiled.result_routes[0].component_id == CLIENT_LANE_COMPONENT_ID
    assert _execute(compiled, (1, 3, 5, 7)) == (6, 0, 35)


def test_uniform_mask_deletion_and_overlap_mask_bypass_fail_closed() -> None:
    component = publish_component(
        {(0, 0): 2},
        rows=1,
        cols=1,
        effective_slots=2,
        version_id="v1",
        component_prefix="base",
    )
    uniform = compile_query((component,), f1m_policy="uniform-random-or-zero")
    program = uniform.cloud_plan.program
    bypassed = replace(
        program,
        ciphertext_inputs=tuple(
            operand for operand in program.ciphertext_inputs if operand.role != "f1m-mask"
        ),
        nodes=(*program.nodes[:-2], ReturnResult("result-000000", program.nodes[-2].ciphertext_id)),
    )
    with pytest.raises(ValueError, match="AddF1MMask"):
        validate_cloud_execution_plan(replace(uniform.cloud_plan, program=bypassed))

    other = publish_component(
        {(0, 0): 3},
        rows=1,
        cols=2,
        effective_slots=2,
        version_id="v1",
        component_prefix="other",
    )
    first = publish_component(
        {(0, 1): 4},
        rows=1,
        cols=2,
        effective_slots=2,
        version_id="v1",
        component_prefix="first",
    )
    overlap = compile_query((other, first), f1m_policy="overlap-only")
    first_mask = next(
        node for node in overlap.cloud_plan.program.nodes if isinstance(node, AddF1MMask)
    )
    tampered_nodes = tuple(
        replace(node, ciphertext_id=first_mask.ciphertext_id)
        if isinstance(node, ReturnResult) and node.ciphertext_id == first_mask.result_id
        else node
        for node in overlap.cloud_plan.program.nodes
        if node is not first_mask
    )
    tampered_program = replace(
        overlap.cloud_plan.program,
        ciphertext_inputs=tuple(
            operand
            for operand in overlap.cloud_plan.program.ciphertext_inputs
            if operand.ciphertext_id != first_mask.mask_ciphertext_id
        ),
        nodes=tampered_nodes,
    )
    tampered_plan = replace(
        overlap.cloud_plan,
        program=tampered_program,
        binding=replace(
            overlap.cloud_plan.binding,
            cloud_program_digest=cloud_program_digest(tampered_program),
        ),
    )
    with pytest.raises(QueryCompilerError, match="F1M policy"):
        validate_compiled_query(replace(overlap, cloud_plan=tampered_plan))
    with pytest.raises(QueryCompilerError, match="F1M policy"):
        execute_compiled_query(
            replace(overlap, cloud_plan=tampered_plan),
            expected_f1m_policy="overlap-only",
            ciphertext_inputs={},
            plaintext_masks={},
            modulus=97,
        )


def test_cloud_bytes_never_expose_private_mask_kind_ci_or_rowmap() -> None:
    left = publish_component(
        {(0, 0): 2},
        rows=1,
        cols=2,
        effective_slots=2,
        version_id="v1",
        component_prefix="left",
    )
    right = publish_component(
        {(0, 1): 3},
        rows=1,
        cols=2,
        effective_slots=2,
        version_id="v1",
        component_prefix="right",
    )

    encoded = canonical_cloud_visible_bytes(
        compile_query((left, right), f1m_policy="overlap-only").cloud_plan
    ).lower()

    for forbidden in (
        b"random-zero-sum",
        b"encrypted-zero-dummy",
        b"column_index",
        b"rowmap",
        b"row_map",
        b"slot_to_logical",
    ):
        assert forbidden not in encoded


def test_overlap_only_rejects_a_disjoint_extra_mask_and_generic_validation_stays_uniform() -> None:
    component = publish_component(
        {(0, 0): 2},
        rows=1,
        cols=1,
        effective_slots=2,
        version_id="v1",
        component_prefix="base",
    )
    compiled = compile_query((component,), f1m_policy="overlap-only")
    with pytest.raises(ValueError, match="AddF1MMask"):
        validate_cloud_execution_plan(compiled.cloud_plan)

    program = compiled.cloud_plan.program
    route = compiled.result_routes[0]
    f1m_id = "ct-f1m-extra"
    masked_id = "ssa-masked-extra"
    return_node = program.nodes[-1]
    assert isinstance(return_node, ReturnResult)
    tampered_program = replace(
        program,
        ciphertext_inputs=(
            *program.ciphertext_inputs,
            CiphertextInput(f1m_id, "f1m-mask", program.slot_count),
        ),
        nodes=(
            *program.nodes[:-1],
            AddF1MMask(masked_id, return_node.ciphertext_id, f1m_id, "opaque-zero-sum"),
            replace(return_node, ciphertext_id=masked_id),
        ),
    )
    tampered_plan = replace(
        compiled.cloud_plan,
        program=tampered_program,
        binding=replace(
            compiled.cloud_plan.binding,
            cloud_program_digest=cloud_program_digest(tampered_program),
        ),
    )
    with pytest.raises(QueryCompilerError, match="F1M policy"):
        validate_compiled_query(
            replace(
                compiled,
                cloud_plan=tampered_plan,
                result_routes=(replace(route, f1m_ciphertext_id=f1m_id),),
            )
        )
    with pytest.raises(QueryCompilerError, match="F1M policy"):
        execute_compiled_query(
            replace(
                compiled,
                cloud_plan=tampered_plan,
                result_routes=(replace(route, f1m_ciphertext_id=f1m_id),),
            ),
            expected_f1m_policy="overlap-only",
            ciphertext_inputs={},
            plaintext_masks={},
            modulus=97,
        )


def test_strong_adapter_is_exactly_the_common_uniform_compilation() -> None:
    base = publish_component(
        {(0, 0): 2, (0, 1): 3, (0, 2): 5},
        rows=2,
        cols=6,
        effective_slots=4,
        version_id="v1",
        component_prefix="base",
    )
    empty = initialize_segmented_delta(
        rows=2,
        cols=6,
        effective_slots=4,
        segment_width=2,
        matrix_value_bound=20,
        version_id="v0",
    )
    delta = advance_segmented_delta(
        empty,
        delta_updates=(),
        overflow_entries=(StrongEntry(1, 5, 7),),
        version_id="v1",
    ).state

    common = compile_query(
        (base,),
        segmented_delta=delta,
        f1m_policy="uniform-random-or-zero",
    )
    strong = compile_strong_execution(base, delta)

    assert strong.cloud_plan == common.cloud_plan
    assert strong.output_plan == common.output_plan
    assert strong.cloud_program_digest == common.cloud_program_digest
    assert strong.output_plan_digest == common.output_plan_digest
    assert strong.execution_binding_digest == common.execution_binding_digest
    assert tuple(
        (
            spec.value_ciphertext_id,
            spec.query_ciphertext_id,
            spec.source_ordinal,
            spec.result_id,
            spec.values,
            spec.global_column_indices,
        )
        for spec in strong.value_operand_specs
    ) == tuple(
        (
            spec.value_ciphertext_id,
            spec.query_ciphertext_id,
            spec.source_ordinal,
            spec.result_id,
            spec.values,
            spec.global_column_indices,
        )
        for spec in common.operand_specs
    )


def test_compiler_fails_closed_on_versions_dimensions_ids_and_coordinate_overlap() -> None:
    base = publish_component(
        {(0, 0): 2},
        rows=1,
        cols=2,
        effective_slots=2,
        version_id="v1",
        component_prefix="base",
    )
    wrong_version = publish_component(
        {(0, 1): 3},
        rows=1,
        cols=2,
        effective_slots=2,
        version_id="v2",
        component_prefix="version",
    )
    wrong_dimensions = publish_component(
        {(0, 1): 3},
        rows=1,
        cols=3,
        effective_slots=2,
        version_id="v1",
        component_prefix="dimensions",
    )
    duplicate_id = publish_component(
        {(0, 1): 3},
        rows=1,
        cols=2,
        effective_slots=2,
        version_id="v1",
        component_prefix="base",
    )
    overlap = publish_component(
        {(0, 0): 3},
        rows=1,
        cols=2,
        effective_slots=2,
        version_id="v1",
        component_prefix="overlap",
    )

    with pytest.raises(QueryCompilerError, match="version_id"):
        compile_query((base, wrong_version))
    with pytest.raises(QueryCompilerError, match="dimensions"):
        compile_query((base, wrong_dimensions))
    with pytest.raises(QueryCompilerError, match="IDs.*unique"):
        compile_query((base, duplicate_id))
    with pytest.raises(QueryCompilerError, match="coordinates.*overlap"):
        compile_query((base, overlap))

    invalid_block = replace(base.blocks[0], output_block_id="bad id")
    with pytest.raises(QueryCompilerError, match="PublishedComponent.*invalid"):
        compile_query((replace(base, blocks=(invalid_block,)),))
