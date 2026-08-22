from __future__ import annotations

import inspect
from dataclasses import replace
from pathlib import Path

import pytest

import dynamic_cssc.output_plan as output_plan_module
from dynamic_cssc.cloud_execution_plan import canonical_cloud_program_bytes
from dynamic_cssc.cssc import publish_component
from dynamic_cssc.mask_ledger import (
    DuplicateMaskBindingError,
    MaskBinding,
    PreparedF1MCommitmentError,
    SQLiteMaskBindingLedger,
)
from dynamic_cssc.strong_execution import (
    PreparedQueryOperand,
    StrongExecutionError,
    compile_strong_execution,
    execute_strong_plaintext,
    prepare_strong_query,
)
from dynamic_cssc.strong_packed_coo import (
    STRONG_COMPONENT_ID,
    StrongEntry,
    advance_segmented_delta,
    initialize_segmented_delta,
)


def test_actual_cssc_base_with_empty_delta_matches_direct_spmv(tmp_path: Path) -> None:
    base = publish_component(
        {(0, 1): 3, (0, 5): 2, (1, 6): -1, (2, 9): 4},
        rows=3,
        cols=12,
        effective_slots=4,
        version_id="version-1",
        component_prefix="base",
    )
    delta = initialize_segmented_delta(
        rows=3,
        cols=12,
        effective_slots=4,
        segment_width=2,
        matrix_value_bound=20,
        version_id="version-1",
    )
    ledger = SQLiteMaskBindingLedger(tmp_path / "mask-ledger.sqlite3")
    bundle = compile_strong_execution(base, delta)
    prepared = prepare_strong_query(
        bundle,
        query_id="query-base-only",
        vector=(0, 5, 0, 0, 0, 7, 11, 0, 0, 13, 0, 0),
        modulus=97,
        ledger=ledger,
    )

    assert execute_strong_plaintext(bundle, prepared, modulus=97, ledger=ledger) == (29, 86, 52)


def test_base_and_one_multi_segment_delta_page_match_direct_spmv(tmp_path: Path) -> None:
    base = publish_component(
        {(0, 1): 3, (0, 5): 2, (1, 6): -1, (2, 9): 4},
        rows=3,
        cols=12,
        effective_slots=4,
        version_id="version-1",
        component_prefix="base",
    )
    empty = initialize_segmented_delta(
        rows=3,
        cols=12,
        effective_slots=4,
        segment_width=2,
        matrix_value_bound=20,
        version_id="version-0",
    )
    delta = advance_segmented_delta(
        empty,
        delta_updates=(),
        overflow_entries=(
            StrongEntry(0, 10, 5),
            StrongEntry(0, 11, -2),
            StrongEntry(1, 9, 4),
        ),
        version_id="version-1",
    ).state

    ledger = SQLiteMaskBindingLedger(tmp_path / "mask-ledger.sqlite3")
    bundle = compile_strong_execution(base, delta)
    prepared = prepare_strong_query(
        bundle,
        query_id="query-base-and-delta",
        vector=(0, 5, 0, 0, 0, 7, 11, 0, 0, 13, 17, 19),
        modulus=97,
        ledger=ledger,
    )

    assert execute_strong_plaintext(bundle, prepared, modulus=97, ledger=ledger) == (76, 41, 52)
    delta_routes = [
        route for route in bundle.result_routes if route.component_id == STRONG_COMPONENT_ID
    ]
    assert len(delta_routes) == 1
    delta_share = next(
        share for share in bundle.output_plan.shares if share.component_id == STRONG_COMPONENT_ID
    )
    assert delta_share.slot_to_logical == ((0, 0), (2, 1))
    assert any(17 in operand.values and 19 in operand.values for operand in prepared.query_operands)


def test_hidden_row_permutation_changes_private_plan_but_not_cloud_program() -> None:
    base = publish_component(
        {(0, 0): 2, (1, 1): 3, (2, 2): 4},
        rows=3,
        cols=16,
        effective_slots=4,
        version_id="version-1",
        component_prefix="base",
    )
    empty = initialize_segmented_delta(
        rows=3,
        cols=16,
        effective_slots=4,
        segment_width=2,
        matrix_value_bound=20,
        version_id="version-0",
    )
    delta = advance_segmented_delta(
        empty,
        delta_updates=(),
        overflow_entries=(StrongEntry(0, 12, 5), StrongEntry(1, 13, 6)),
        version_id="version-1",
    ).state
    owner_permutation = (2, 0, 1)
    permuted_blocks = []
    placements = []
    for block in base.blocks:
        chunks = []
        for chunk in block.chunks:
            owners = tuple(
                None if owner is None else owner_permutation[owner]
                for owner in chunk.slot_owner_rows
            )
            coordinates = tuple(
                None if coordinate is None else (owner_permutation[coordinate[0]], coordinate[1])
                for coordinate in chunk.slot_coordinates
            )
            chunks.append(replace(chunk, slot_owner_rows=owners, slot_coordinates=coordinates))
            placements.extend(
                (coordinate, (base.component_id, chunk.chunk_id, lane))
                for lane, coordinate in enumerate(coordinates)
                if coordinate is not None
            )
        permuted_blocks.append(
            replace(
                block,
                row_map=tuple(owner_permutation[row] for row in block.row_map),
                chunks=tuple(chunks),
            )
        )
    permuted_base = replace(
        base,
        blocks=tuple(permuted_blocks),
        _coordinate_slots=tuple(sorted(placements)),
    )
    permuted_delta = replace(
        delta,
        segments=tuple(
            replace(
                segment,
                owner_row=owner_permutation[segment.owner_row],
                entries=tuple(
                    None if entry is None else replace(entry, row=owner_permutation[entry.row])
                    for entry in segment.entries
                ),
            )
            for segment in delta.segments
        ),
    )

    original = compile_strong_execution(base, delta)
    permuted = compile_strong_execution(permuted_base, permuted_delta)

    assert original.output_plan != permuted.output_plan
    assert original.private_plan_digest != permuted.private_plan_digest
    assert canonical_cloud_program_bytes(original.cloud_plan.program) == (
        canonical_cloud_program_bytes(permuted.cloud_plan.program)
    )


class _RecordingLedger:
    def __init__(self) -> None:
        self.bindings: tuple[MaskBinding, ...] = ()
        self.commitments = ()
        self.consumed = False

    def reserve_all(self, bindings) -> None:
        self.bindings = tuple(bindings)

    def commit_prepared_f1m(self, commitments, **_) -> str:
        self.commitments = tuple(commitments)
        return "f" * 64

    def verify_and_consume_prepared_f1m(self, commitments, **_) -> None:
        if self.consumed:
            raise RuntimeError("prepared F1-M commitment batch was already consumed")
        if tuple(commitments) != self.commitments:
            raise RuntimeError("prepared F1-M commitment values do not match the ledger")
        self.consumed = True


def _three_result_bundle():
    base = publish_component(
        {(0, 1): 3, (3, 7): 4},
        rows=4,
        cols=12,
        effective_slots=4,
        partition_rows=2,
        version_id="version-1",
        component_prefix="base",
    )
    empty = initialize_segmented_delta(
        rows=4,
        cols=12,
        effective_slots=4,
        segment_width=2,
        matrix_value_bound=20,
        version_id="version-0",
    )
    delta = advance_segmented_delta(
        empty,
        delta_updates=(),
        overflow_entries=(StrongEntry(0, 10, 5),),
        version_id="version-1",
    ).state
    return compile_strong_execution(base, delta)


def test_every_return_uses_random_or_exact_zero_dummy_f1m_and_counts_from_dag() -> None:
    bundle = _three_result_bundle()
    ledger = _RecordingLedger()

    prepared = prepare_strong_query(
        bundle,
        query_id="query-f1m",
        vector=tuple(range(12)),
        modulus=97,
        ledger=ledger,
    )

    assert [operand.kind for operand in prepared.f1m_operands] == [
        "random-zero-sum",
        "encrypted-zero-dummy",
        "random-zero-sum",
    ]
    assert prepared.f1m_operands[1].values == (0, 0, 0, 0)
    assert [(binding[3], binding[4]) for binding in ledger.bindings] == [
        ("base", "base-h000000"),
        (STRONG_COMPONENT_ID, "page-000000"),
    ]
    assert bundle.f1m_counts.random_zero_sum_ciphertexts == 2
    assert bundle.f1m_counts.encrypted_zero_dummy_ciphertexts == 1
    assert bundle.f1m_counts.random_elements == 1
    assert bundle.cloud_counts.ciphertext_inputs_by_role == (
        ("f1m-mask", 3),
        ("query", 3),
        ("value", 3),
    )
    assert bundle.cloud_counts.multiply_ciphertexts == 3
    assert bundle.cloud_counts.relinearizations == 3
    assert bundle.cloud_counts.rotations_by_exact_index == ((1, 1),)
    assert bundle.cloud_counts.add_ciphertexts == 1
    assert bundle.cloud_counts.multiply_plaintext_masks == 3
    assert bundle.cloud_counts.add_f1m_masks == 3
    assert bundle.cloud_counts.returned_ciphertexts == 3


def test_duplicate_random_mask_query_fails_closed(tmp_path: Path) -> None:
    bundle = _three_result_bundle()
    ledger = SQLiteMaskBindingLedger(tmp_path / "mask-ledger.sqlite3")
    arguments = {
        "query_id": "query-reused",
        "vector": tuple(range(12)),
        "modulus": 97,
        "ledger": ledger,
    }

    prepare_strong_query(bundle, **arguments)

    with pytest.raises(DuplicateMaskBindingError):
        prepare_strong_query(bundle, **arguments)


def test_frozen_large_shape_has_exact_reductions_global_ci_and_segment_tail() -> None:
    base = publish_component(
        {(0, 0): 2, (0, 1): 3, (0, 8192): 4, (3, 7): 5},
        rows=4,
        cols=8193,
        effective_slots=4096,
        partition_rows=2,
        version_id="version-large",
        component_prefix="base",
    )
    empty = initialize_segmented_delta(
        rows=4,
        cols=8193,
        effective_slots=4096,
        segment_width=128,
        matrix_value_bound=200,
        version_id="version-0",
    )
    delta = advance_segmented_delta(
        empty,
        delta_updates=(),
        overflow_entries=tuple(StrongEntry(0, 100 + offset, 1) for offset in range(127)),
        version_id="version-large",
    ).state
    bundle = compile_strong_execution(base, delta)
    vector = [0] * 8193
    vector[8192] = 19

    prepared = prepare_strong_query(
        bundle,
        query_id="query-large",
        vector=tuple(vector),
        modulus=65537,
        ledger=_RecordingLedger(),
    )

    assert bundle.cloud_counts.multiply_ciphertexts == 3
    assert bundle.cloud_counts.relinearizations == 3
    assert bundle.cloud_counts.rotations == 9
    assert bundle.cloud_counts.rotations_by_exact_index == (
        (1, 2),
        (2, 2),
        (4, 1),
        (8, 1),
        (16, 1),
        (32, 1),
        (64, 1),
    )
    assert bundle.cloud_counts.add_ciphertexts == 9
    assert bundle.cloud_counts.multiply_plaintext_masks == 3
    assert bundle.cloud_counts.add_f1m_masks == 3
    assert bundle.cloud_counts.returned_ciphertexts == 3
    assert [operand.kind for operand in prepared.f1m_operands] == [
        "random-zero-sum",
        "encrypted-zero-dummy",
        "random-zero-sum",
    ]
    base_width_three = next(
        spec
        for spec in bundle.value_operand_specs
        if spec.source_kind == "base-chunk" and 8192 in spec.global_column_indices
    )
    delta_page = next(
        spec for spec in bundle.value_operand_specs if spec.source_kind == "delta-page"
    )
    query = next(
        operand
        for operand in prepared.query_operands
        if operand.ciphertext_id == base_width_three.query_ciphertext_id
    )
    assert query.values[base_width_three.global_column_indices.index(8192)] == 19
    assert delta_page.values[126] == 1
    assert delta_page.values[127] == 0


def test_binding_route_program_private_ci_and_count_tampering_fail_closed() -> None:
    bundle = _three_result_bundle()
    program = bundle.cloud_plan.program
    tampered_program = replace(
        program,
        plaintext_masks=(
            replace(program.plaintext_masks[0], values=(0,) * program.slot_count),
            *program.plaintext_masks[1:],
        ),
    )
    first_spec = bundle.value_operand_specs[0]
    tampered_ci = replace(
        first_spec,
        global_column_indices=(11, *first_spec.global_column_indices[1:]),
    )
    variants = (
        replace(
            bundle,
            cloud_plan=replace(
                bundle.cloud_plan,
                binding=replace(bundle.cloud_plan.binding, version_id="other-version"),
            ),
        ),
        replace(
            bundle,
            result_routes=(
                replace(bundle.result_routes[0], output_block_id="other-block"),
                *bundle.result_routes[1:],
            ),
        ),
        replace(bundle, cloud_plan=replace(bundle.cloud_plan, program=tampered_program)),
        replace(bundle, value_operand_specs=(tampered_ci, *bundle.value_operand_specs[1:])),
        replace(
            bundle,
            cloud_counts=replace(
                bundle.cloud_counts,
                returned_ciphertexts=bundle.cloud_counts.returned_ciphertexts + 1,
            ),
        ),
    )

    for tampered in variants:
        with pytest.raises(StrongExecutionError, match="deterministically derived"):
            prepare_strong_query(
                tampered,
                query_id="query-tampered",
                vector=tuple(range(12)),
                modulus=97,
                ledger=_RecordingLedger(),
            )


def test_compile_rejects_inconsistent_actual_cssc_lane_metadata() -> None:
    base = publish_component(
        {(0, 1): 3},
        rows=2,
        cols=12,
        effective_slots=4,
        version_id="version-1",
        component_prefix="base",
    )
    chunk = base.blocks[0].chunks[0]
    columns = (12, *chunk.column_indices[1:])
    coordinates = ((0, 12), *chunk.slot_coordinates[1:])
    tampered_chunk = replace(
        chunk,
        column_indices=columns,
        slot_coordinates=coordinates,
    )
    tampered_base = replace(
        base,
        blocks=(replace(base.blocks[0], chunks=(tampered_chunk,)),),
        _coordinate_slots=(((0, 12), (base.component_id, chunk.chunk_id, 0)),),
    )
    delta = initialize_segmented_delta(
        rows=2,
        cols=12,
        effective_slots=4,
        segment_width=2,
        matrix_value_bound=20,
        version_id="version-1",
    )

    with pytest.raises(StrongExecutionError, match="base.*invalid"):
        compile_strong_execution(tampered_base, delta)


def test_public_seam_does_not_accept_caller_supplied_ids_nodes_counts_or_masks() -> None:
    assert tuple(inspect.signature(compile_strong_execution).parameters) == ("base", "delta")
    assert tuple(inspect.signature(prepare_strong_query).parameters) == (
        "bundle",
        "query_id",
        "vector",
        "modulus",
        "ledger",
    )
    assert tuple(inspect.signature(execute_strong_plaintext).parameters) == (
        "bundle",
        "prepared",
        "modulus",
        "ledger",
    )


@pytest.mark.parametrize(
    ("rows", "cols", "effective_slots", "version_id", "message"),
    (
        (2, 12, 4, "version-2", "version_id"),
        (3, 12, 4, "version-1", "dimensions"),
        (2, 13, 4, "version-1", "dimensions"),
        (2, 12, 8, "version-1", "dimensions"),
    ),
)
def test_compile_rejects_mismatched_version_matrix_or_slots(
    rows: int,
    cols: int,
    effective_slots: int,
    version_id: str,
    message: str,
) -> None:
    base = publish_component(
        {(0, 1): 3},
        rows=2,
        cols=12,
        effective_slots=4,
        version_id="version-1",
        component_prefix="base",
    )
    delta = initialize_segmented_delta(
        rows=rows,
        cols=cols,
        effective_slots=effective_slots,
        segment_width=2,
        matrix_value_bound=20,
        version_id=version_id,
    )

    with pytest.raises(StrongExecutionError, match=message):
        compile_strong_execution(base, delta)


def test_compile_rejects_overlapping_active_coordinates() -> None:
    base = publish_component(
        {(0, 1): 3},
        rows=2,
        cols=12,
        effective_slots=4,
        version_id="version-1",
        component_prefix="base",
    )
    empty = initialize_segmented_delta(
        rows=2,
        cols=12,
        effective_slots=4,
        segment_width=2,
        matrix_value_bound=20,
        version_id="version-0",
    )
    delta = advance_segmented_delta(
        empty,
        delta_updates=(),
        overflow_entries=(StrongEntry(0, 1, 4),),
        version_id="version-1",
    ).state

    with pytest.raises(StrongExecutionError, match="active.*disjoint"):
        compile_strong_execution(base, delta)


def test_prepared_dummy_operand_tampering_fails_closed() -> None:
    bundle = _three_result_bundle()
    ledger = _RecordingLedger()
    prepared = prepare_strong_query(
        bundle,
        query_id="query-dummy-tamper",
        vector=tuple(range(12)),
        modulus=97,
        ledger=ledger,
    )
    dummy = prepared.f1m_operands[1]
    tampered = replace(
        prepared,
        f1m_operands=(
            prepared.f1m_operands[0],
            replace(dummy, values=(1, *dummy.values[1:])),
            prepared.f1m_operands[2],
        ),
    )

    with pytest.raises(StrongExecutionError, match="exactly zero"):
        execute_strong_plaintext(bundle, tampered, modulus=97, ledger=ledger)


def test_execution_rejects_consistent_query_id_relabel(
    tmp_path: Path,
) -> None:
    bundle = _three_result_bundle()
    ledger = SQLiteMaskBindingLedger(tmp_path / "mask-ledger.sqlite3")
    prepared = prepare_strong_query(
        bundle,
        query_id="query-original",
        vector=tuple(range(12)),
        modulus=97,
        ledger=ledger,
    )
    relabeled = replace(
        prepared,
        query_id="query-relabeled",
        f1m_operands=tuple(
            replace(operand, query_id="query-relabeled") for operand in prepared.f1m_operands
        ),
    )

    with pytest.raises(RuntimeError, match="prepared F1-M commitment"):
        execute_strong_plaintext(bundle, relabeled, modulus=97, ledger=ledger)


def test_execution_rejects_other_valid_query_masks_without_consuming_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _three_result_bundle()
    ledger = SQLiteMaskBindingLedger(tmp_path / "mask-ledger.sqlite3")
    samples = iter((5, 7))
    monkeypatch.setattr(output_plan_module.secrets, "randbelow", lambda _: next(samples))
    query_one = prepare_strong_query(
        bundle,
        query_id="query-one",
        vector=tuple(range(12)),
        modulus=97,
        ledger=ledger,
    )
    query_two = prepare_strong_query(
        bundle,
        query_id="query-two",
        vector=tuple(range(12)),
        modulus=97,
        ledger=ledger,
    )
    substituted = replace(
        query_two,
        f1m_operands=tuple(
            replace(target, values=source.values)
            for target, source in zip(
                query_two.f1m_operands,
                query_one.f1m_operands,
                strict=True,
            )
        ),
    )

    with pytest.raises(RuntimeError, match="prepared F1-M commitment"):
        execute_strong_plaintext(bundle, substituted, modulus=97, ledger=ledger)

    assert execute_strong_plaintext(
        bundle,
        query_two,
        modulus=97,
        ledger=ledger,
    ) == (53, 0, 0, 28)


def test_execution_consumes_prepared_f1m_commitments_exactly_once(
    tmp_path: Path,
) -> None:
    bundle = _three_result_bundle()
    ledger_path = tmp_path / "mask-ledger.sqlite3"
    ledger = SQLiteMaskBindingLedger(ledger_path)
    prepared = prepare_strong_query(
        bundle,
        query_id="query-once",
        vector=tuple(range(12)),
        modulus=97,
        ledger=ledger,
    )

    assert execute_strong_plaintext(
        bundle,
        prepared,
        modulus=97,
        ledger=SQLiteMaskBindingLedger(ledger_path),
    ) == (53, 0, 0, 28)
    with pytest.raises(RuntimeError, match="already consumed"):
        execute_strong_plaintext(
            bundle,
            prepared,
            modulus=97,
            ledger=SQLiteMaskBindingLedger(ledger_path),
        )


def test_dummy_only_query_binding_cannot_be_prepared_twice(tmp_path: Path) -> None:
    base = publish_component(
        {(0, 1): 3},
        rows=2,
        cols=4,
        effective_slots=4,
        version_id="version-1",
        component_prefix="base",
    )
    delta = initialize_segmented_delta(
        rows=2,
        cols=4,
        effective_slots=4,
        segment_width=2,
        matrix_value_bound=20,
        version_id="version-1",
    )
    bundle = compile_strong_execution(base, delta)
    ledger = SQLiteMaskBindingLedger(tmp_path / "mask-ledger.sqlite3")
    arguments = {
        "query_id": "query-dummy-once",
        "vector": (0, 5, 0, 0),
        "modulus": 97,
        "ledger": ledger,
    }

    prepare_strong_query(bundle, **arguments)

    with pytest.raises(DuplicateMaskBindingError):
        prepare_strong_query(bundle, **arguments)


def test_execution_rejects_token_retarget_to_different_private_plan_without_consuming(
    tmp_path: Path,
) -> None:
    base_one = publish_component(
        {(0, 1): 3},
        rows=2,
        cols=4,
        effective_slots=4,
        version_id="version-1",
        component_prefix="base",
    )
    base_two = publish_component(
        {(0, 2): 5},
        rows=2,
        cols=4,
        effective_slots=4,
        version_id="version-1",
        component_prefix="base",
    )
    delta = initialize_segmented_delta(
        rows=2,
        cols=4,
        effective_slots=4,
        segment_width=2,
        matrix_value_bound=20,
        version_id="version-1",
    )
    original_bundle = compile_strong_execution(base_one, delta)
    target_bundle = compile_strong_execution(base_two, delta)
    assert original_bundle.output_plan == target_bundle.output_plan
    assert canonical_cloud_program_bytes(original_bundle.cloud_plan.program) == (
        canonical_cloud_program_bytes(target_bundle.cloud_plan.program)
    )
    assert original_bundle.private_plan_digest != target_bundle.private_plan_digest
    ledger = SQLiteMaskBindingLedger(tmp_path / "mask-ledger.sqlite3")
    vector = (0, 7, 11, 0)
    prepared = prepare_strong_query(
        original_bundle,
        query_id="query-private-plan",
        vector=vector,
        modulus=97,
        ledger=ledger,
    )
    target_queries = tuple(
        PreparedQueryOperand(
            ciphertext_id=spec.query_ciphertext_id,
            values=tuple(
                vector[global_column] if global_column >= 0 else 0
                for global_column in spec.global_column_indices
            ),
        )
        for spec in target_bundle.value_operand_specs
    )
    retargeted = replace(
        prepared,
        private_plan_digest=target_bundle.private_plan_digest,
        query_operands=target_queries,
    )

    with pytest.raises(PreparedF1MCommitmentError, match="private plan"):
        execute_strong_plaintext(
            target_bundle,
            retargeted,
            modulus=97,
            ledger=ledger,
        )

    assert execute_strong_plaintext(
        original_bundle,
        prepared,
        modulus=97,
        ledger=ledger,
    ) == (21, 0)


def test_execution_rejects_token_retarget_to_different_cloud_dag_without_consuming(
    tmp_path: Path,
) -> None:
    common = {
        "rows": 2,
        "cols": 8,
        "effective_slots": 8,
        "version_id": "version-1",
        "component_prefix": "base",
    }
    width_two = publish_component(
        {(0, 0): 2, (0, 1): 3},
        physical_capacities=(2, 0),
        **common,
    )
    width_four = publish_component(
        {(0, 0): 2, (0, 1): 3},
        physical_capacities=(4, 0),
        **common,
    )
    delta = initialize_segmented_delta(
        rows=2,
        cols=8,
        effective_slots=8,
        segment_width=2,
        matrix_value_bound=20,
        version_id="version-1",
    )
    original_bundle = compile_strong_execution(width_two, delta)
    target_bundle = compile_strong_execution(width_four, delta)
    assert original_bundle.output_plan == target_bundle.output_plan
    assert original_bundle.private_plan_digest == target_bundle.private_plan_digest
    assert original_bundle.result_routes == target_bundle.result_routes
    assert original_bundle.cloud_program_digest != target_bundle.cloud_program_digest
    assert original_bundle.execution_binding_digest != target_bundle.execution_binding_digest
    ledger = SQLiteMaskBindingLedger(tmp_path / "mask-ledger.sqlite3")
    prepared = prepare_strong_query(
        original_bundle,
        query_id="query-cloud-dag",
        vector=(5, 7, 0, 0, 0, 0, 0, 0),
        modulus=97,
        ledger=ledger,
    )
    retargeted = replace(
        prepared,
        cloud_program_digest=target_bundle.cloud_program_digest,
        execution_binding_digest=target_bundle.execution_binding_digest,
    )

    with pytest.raises(PreparedF1MCommitmentError, match="execution binding"):
        execute_strong_plaintext(
            target_bundle,
            retargeted,
            modulus=97,
            ledger=ledger,
        )

    assert execute_strong_plaintext(
        original_bundle,
        prepared,
        modulus=97,
        ledger=ledger,
    ) == (31, 0)
