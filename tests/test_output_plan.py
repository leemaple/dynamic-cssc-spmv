from __future__ import annotations

import pytest

from dynamic_cssc.output_plan import (
    OutputPlan,
    OutputPlanError,
    OutputShare,
    analyze_output_plan,
    prepare_f1m_masks,
)


def test_disjoint_output_blocks_are_concatenated_without_masks() -> None:
    plan = OutputPlan(
        logical_output_size=4,
        slot_count=4,
        shares=(
            OutputShare("base-left", "rows-0-1", ((0, 0), (1, 1))),
            OutputShare("base-right", "rows-2-3", ((0, 2), (1, 3))),
        ),
    )

    analysis = analyze_output_plan(plan)

    assert analysis.reconstruction_mode == "concatenate"
    assert analysis.result_ciphertexts == 2
    assert analysis.masked_result_ciphertexts == 0
    assert analysis.overlap_coordinates == 0
    assert analysis.mask_random_elements == 0
    assert analysis.mask_mapped_elements == 0
    assert analysis.client_reorder_elements == 4
    assert analysis.client_modular_additions == 0


def test_overlapping_shares_receive_physical_zero_sum_masks() -> None:
    plan = OutputPlan(
        logical_output_size=4,
        slot_count=4,
        shares=(
            OutputShare("base", "all", ((0, 0), (1, 1), (2, 2), (3, 3))),
            OutputShare("delta", "all", ((0, 3), (1, 2), (2, 1), (3, 0))),
        ),
    )
    samples = iter((1, 2, 3, 4))

    masks = prepare_f1m_masks(
        plan,
        query_id="query-7",
        version_id="version-3",
        modulus=17,
        randbelow=lambda _: next(samples),
    )

    assert [(mask.component_id, mask.output_block_id) for mask in masks] == [
        ("base", "all"),
        ("delta", "all"),
    ]
    assert masks[0].values == (1, 2, 3, 4)
    assert masks[1].values == (13, 14, 15, 16)
    assert masks[0].binding == (
        "query-7",
        "version-3",
        masks[0].output_plan_digest,
        "base",
        "all",
    )
    analysis = analyze_output_plan(plan)
    assert analysis.masked_result_ciphertexts == 2
    assert analysis.mask_random_elements == 4
    assert analysis.mask_mapped_elements == 8
    assert analysis.client_modular_additions == 4


def test_partial_overlap_masks_only_the_contributing_ciphertexts() -> None:
    plan = OutputPlan(
        logical_output_size=4,
        slot_count=4,
        shares=(
            OutputShare("base-left", "rows-0-1", ((0, 0), (1, 1))),
            OutputShare("delta", "row-1", ((3, 1),)),
            OutputShare("base-right", "rows-2-3", ((0, 2), (1, 3))),
        ),
    )

    masks = prepare_f1m_masks(
        plan,
        query_id="q",
        version_id="v",
        modulus=17,
        randbelow=lambda _: 6,
    )

    assert [(mask.component_id, mask.values) for mask in masks] == [
        ("base-left", (0, 6, 0, 0)),
        ("delta", (0, 0, 0, 11)),
    ]
    analysis = analyze_output_plan(plan)
    assert analysis.result_ciphertexts == 3
    assert analysis.masked_result_ciphertexts == 2
    assert analysis.mask_random_elements == 1
    assert analysis.mask_mapped_elements == 2
    assert analysis.client_reorder_elements == 5
    assert analysis.client_modular_additions == 1


def test_three_contributors_use_two_random_values_and_one_completion() -> None:
    plan = OutputPlan(
        logical_output_size=1,
        slot_count=2,
        shares=(
            OutputShare("a", "out", ((0, 0),)),
            OutputShare("b", "out", ((1, 0),)),
            OutputShare("c", "out", ((0, 0),)),
        ),
    )
    samples = iter((5, 7))

    masks = prepare_f1m_masks(
        plan,
        query_id="q",
        version_id="v",
        modulus=17,
        randbelow=lambda _: next(samples),
    )

    assert [mask.values for mask in masks] == [(5, 0), (0, 7), (5, 0)]
    assert analyze_output_plan(plan).mask_random_elements == 2


def test_digest_is_canonical_but_changes_with_output_semantics() -> None:
    plan = OutputPlan(
        logical_output_size=2,
        slot_count=4,
        shares=(
            OutputShare("z", "right", ((1, 1),)),
            OutputShare("a", "left", ((3, 0),)),
        ),
    )
    reordered = OutputPlan(
        logical_output_size=2,
        slot_count=4,
        shares=(
            OutputShare("a", "left", ((3, 0),)),
            OutputShare("z", "right", ((1, 1),)),
        ),
    )
    changed_slot = OutputPlan(
        logical_output_size=2,
        slot_count=4,
        shares=(
            OutputShare("a", "left", ((2, 0),)),
            OutputShare("z", "right", ((1, 1),)),
        ),
    )

    digest = analyze_output_plan(plan).output_plan_digest

    assert digest == "3954eda197eebd8d32ccb6dd477c6515be3dc38a6a29b9f1240894e60edbf196"
    assert digest == analyze_output_plan(reordered).output_plan_digest
    assert digest != analyze_output_plan(changed_slot).output_plan_digest
    assert len(digest) == 64


@pytest.mark.parametrize(
    "plan",
    [
        OutputPlan(2, 2, (OutputShare("base", "out", ((0, 0),)),)),
        OutputPlan(1, 1, (OutputShare("base", "out", ((0, 0), (0, 0))),)),
        OutputPlan(1, 1, (OutputShare("base id", "out", ((0, 0),)),)),
        OutputPlan(
            1,
            1,
            (
                OutputShare("base", "out", ((0, 0),)),
                OutputShare("base", "out", ((0, 0),)),
            ),
        ),
    ],
)
def test_ambiguous_output_plans_are_rejected(plan: OutputPlan) -> None:
    with pytest.raises(OutputPlanError):
        analyze_output_plan(plan)


def test_random_adapter_must_return_an_element_of_z_t() -> None:
    plan = OutputPlan(
        logical_output_size=1,
        slot_count=1,
        shares=(
            OutputShare("base", "out", ((0, 0),)),
            OutputShare("delta", "out", ((0, 0),)),
        ),
    )

    with pytest.raises(OutputPlanError, match="outside Z_t"):
        prepare_f1m_masks(
            plan,
            query_id="q",
            version_id="v",
            modulus=17,
            randbelow=lambda _: 17,
        )
