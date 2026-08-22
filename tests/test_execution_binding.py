from __future__ import annotations

from dataclasses import replace

import pytest

from dynamic_cssc.cloud_execution_plan import (
    CLOUD_EXECUTION_PLAN_FORMAT,
    CLOUD_PROGRAM_FORMAT,
    EXECUTION_BINDING_FORMAT,
    AddF1MMask,
    CiphertextInput,
    CloudExecutionPlan,
    CloudExecutionPlanError,
    CloudPlanCounts,
    CloudProgram,
    ExecutionBinding,
    MultiplyCiphertexts,
    MultiplyPlaintextMask,
    PlaintextMask,
    Relinearize,
    ReturnResult,
    Rotate,
    RotationCatalog,
    analyze_cloud_plan,
    canonical_cloud_visible_bytes,
    canonical_cloud_visible_payload,
    cloud_program_digest,
    execution_binding_digest,
    validate_cloud_execution_plan,
)


def _program() -> CloudProgram:
    return CloudProgram(
        format=CLOUD_PROGRAM_FORMAT,
        slot_count=4,
        ciphertext_inputs=(
            CiphertextInput("values", "value", 4),
            CiphertextInput("query", "query", 4),
            CiphertextInput("mask", "f1m-mask", 4),
        ),
        plaintext_masks=(PlaintextMask("starts", "selection", 4, (1, 0, 0, 0)),),
        nodes=(
            MultiplyCiphertexts("product", "values", "query"),
            Relinearize("relinearized", "product"),
            MultiplyPlaintextMask("selected", "relinearized", "starts"),
            AddF1MMask("masked", "selected", "mask", "opaque-zero-sum"),
            ReturnResult("page-0", "masked"),
        ),
        result_ids=("page-0",),
        rotation_catalog=RotationCatalog(()),
    )


def _plan() -> CloudExecutionPlan:
    program = _program()
    return CloudExecutionPlan(
        program=program,
        binding=ExecutionBinding(
            format=EXECUTION_BINDING_FORMAT,
            version_id="version-7",
            output_plan_digest="a" * 64,
            cloud_program_digest=cloud_program_digest(program),
        ),
    )


def test_binding_atomically_commits_version_output_plan_and_public_program() -> None:
    plan = _plan()

    validate_cloud_execution_plan(plan)

    payload = canonical_cloud_visible_payload(plan)
    assert set(payload) == {"binding", "format", "program"}
    assert payload["format"] == CLOUD_EXECUTION_PLAN_FORMAT
    assert payload["binding"] == {
        "cloud_program_digest": cloud_program_digest(plan.program),
        "format": EXECUTION_BINDING_FORMAT,
        "output_plan_digest": "a" * 64,
        "version_id": "version-7",
    }
    assert canonical_cloud_visible_bytes(plan).startswith(b'{"binding":{"cloud_program_digest":"')
    assert cloud_program_digest(plan.program) == (
        "6a61641f9f338c8aa7e95d79124e299c7fff3d35ae685463e632cb14636df4ff"
    )
    assert execution_binding_digest(plan.binding) == (
        "fe45fa19a4e1ceacb64ff73d7b2f26377eb51e08022496b55395bb7e25fa4eda"
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("version_id", "version-8"),
        ("output_plan_digest", "b" * 64),
        ("cloud_program_digest", "c" * 64),
    ),
)
def test_binding_digest_changes_if_any_atomic_binding_field_changes(field: str, value: str) -> None:
    binding = _plan().binding

    assert execution_binding_digest(replace(binding, **{field: value})) != (
        execution_binding_digest(binding)
    )


def test_plan_rejects_a_binding_to_different_program_bytes() -> None:
    plan = _plan()

    with pytest.raises(CloudExecutionPlanError, match="cloud_program_digest"):
        validate_cloud_execution_plan(
            replace(
                plan,
                binding=replace(plan.binding, cloud_program_digest="0" * 64),
            )
        )


def test_counts_are_folded_from_typed_nodes_and_exact_rotation_indices() -> None:
    plan = _plan()

    assert analyze_cloud_plan(plan) == CloudPlanCounts(
        ciphertext_inputs=3,
        ciphertext_inputs_by_role=(("f1m-mask", 1), ("query", 1), ("value", 1)),
        plaintext_masks=1,
        multiply_ciphertexts=1,
        relinearizations=1,
        rotations=0,
        rotations_by_exact_index=(),
        multiply_plaintext_masks=1,
        add_ciphertexts=0,
        add_f1m_masks=1,
        returned_ciphertexts=1,
    )


def test_rotation_counts_use_verified_openfhe_indices_not_logical_shifts() -> None:
    base = _program()
    selected = replace(base.nodes[2], ciphertext_id="rotated")
    rotating_program = replace(
        base,
        nodes=(
            *base.nodes[:2],
            Rotate("rotated", "relinearized", 1, 37),
            selected,
            *base.nodes[3:],
        ),
        rotation_catalog=RotationCatalog(((1, 37),)),
    )
    plan = CloudExecutionPlan(
        program=rotating_program,
        binding=ExecutionBinding(
            format=EXECUTION_BINDING_FORMAT,
            version_id="version-7",
            output_plan_digest="a" * 64,
            cloud_program_digest=cloud_program_digest(rotating_program),
        ),
    )

    counts = analyze_cloud_plan(plan)

    assert counts.rotations == 1
    assert counts.rotations_by_exact_index == ((37, 1),)


def test_public_plaintext_mask_values_are_committed_by_the_program_digest() -> None:
    program = _program()
    tampered_mask = PlaintextMask("starts", "selection", 4, (0, 0, 0, 0))

    assert cloud_program_digest(replace(program, plaintext_masks=(tampered_mask,))) != (
        cloud_program_digest(program)
    )
