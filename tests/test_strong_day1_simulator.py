from __future__ import annotations

import pytest

from dynamic_cssc.events import NetUpdate, PublicationWindow
from dynamic_cssc.simulator import (
    STRONG_REFERENCE_STRATEGY,
    SimulationConfig,
    SimulationTarget,
    account_strong_transition,
    simulate,
    simulate_strong_reference,
    simulate_targets,
)
from dynamic_cssc.strategy_state import (
    STRATEGIES,
    advance_strong_publication,
    initialize_strong_strategy,
)


def _config(**overrides: object) -> SimulationConfig:
    values: dict[str, object] = {
        "rows": 2,
        "cols": 4,
        "effective_slots": 128,
        "partition_rows": 1,
        "matrix_value_bound": 7,
        "max_row_nnz": 4,
        "reserved_slack_beta": 0.75,
        "periodic_repack_windows": 1,
        "packed_coo_segment_capacity": 1,
    }
    values.update(overrides)
    return SimulationConfig(**values)  # type: ignore[arg-type]


def _window(*, index: int, queries: int) -> PublicationWindow:
    return PublicationWindow(
        index=index,
        start_time=float(index),
        end_time=float(index),
        updates=(),
        query_count=queries,
        reason="query" if queries else "version",
    )


def test_strong_query_only_accounting_uses_uniform_dummy_f1m() -> None:
    result = simulate_strong_reference(
        [_window(index=0, queries=2)],
        {(0, 0): 1, (1, 0): 2},
        _config(),
        measure_from=0,
    )

    metrics = result.metrics
    assert metrics.strategy == "Packed-COO-Cloud-Segmented-Delta"
    assert metrics.windows == 1
    assert metrics.queries == 2
    assert metrics.updates == 0
    assert (
        metrics.query_ciphertexts,
        metrics.cc_multiplications,
        metrics.relinearizations,
        metrics.rotations,
        metrics.additions,
        metrics.plaintext_masks,
        metrics.result_ciphertexts,
    ) == (4, 4, 4, 0, 0, 4, 4)
    assert (
        metrics.blinding_mask_ciphertexts,
        metrics.blinding_dummy_ciphertexts,
        metrics.blinding_encryptions,
        metrics.blinding_additions,
    ) == (0, 4, 4, 4)
    assert (
        metrics.decryptions,
        metrics.client_reorder_elements,
        metrics.client_merges,
        metrics.mask_random_elements,
        metrics.mask_mapped_elements,
    ) == (4, 4, 0, 0, 0)
    assert result.rotation_inventory.measured_counts_by_exact_index == ()
    assert result.rotation_inventory.required_indices == ()


def test_strong_delta_accounts_update_dag_mixed_f1m_and_exact_c128_rotations() -> None:
    result = simulate_strong_reference(
        [
            PublicationWindow(
                index=0,
                start_time=0.0,
                end_time=0.0,
                updates=(NetUpdate(row=0, col=1, before=0, after=3),),
                query_count=1,
                reason="query",
            )
        ],
        {(0, 0): 1, (1, 0): 2},
        _config(),
        measure_from=0,
    )

    metrics = result.metrics
    assert (
        metrics.update_encryptions,
        metrics.update_ciphertexts,
        metrics.compaction_ciphertexts,
        metrics.ci_patch_entries,
        metrics.ci_full_sync_entries,
        metrics.metadata_units,
        metrics.overflow_updates,
    ) == (1, 1, 0, 0, 128, 128, 1)
    assert (
        metrics.query_ciphertexts,
        metrics.cc_multiplications,
        metrics.relinearizations,
        metrics.rotations,
        metrics.additions,
        metrics.plaintext_masks,
        metrics.result_ciphertexts,
    ) == (3, 3, 3, 7, 7, 3, 3)
    assert (
        metrics.blinding_mask_ciphertexts,
        metrics.blinding_dummy_ciphertexts,
        metrics.blinding_encryptions,
        metrics.blinding_additions,
    ) == (2, 1, 3, 3)
    assert (
        metrics.decryptions,
        metrics.client_reorder_elements,
        metrics.client_merges,
        metrics.mask_random_elements,
        metrics.mask_mapped_elements,
    ) == (3, 3, 1, 1, 2)
    assert result.rotation_inventory.measured_counts_by_exact_index == (
        (1, 1),
        (2, 1),
        (4, 1),
        (8, 1),
        (16, 1),
        (32, 1),
        (64, 1),
    )
    assert result.rotation_inventory.required_indices == (1, 2, 4, 8, 16, 32, 64)


def test_strong_window_accounting_classifies_random_and_dummy_routes() -> None:
    initial = {(0, 0): 1, (1, 0): 2}
    window = PublicationWindow(
        index=0,
        start_time=0.0,
        end_time=0.0,
        updates=(NetUpdate(row=0, col=1, before=0, after=3),),
        query_count=5,
        reason="query",
    )
    state = initialize_strong_strategy(
        initial,
        rows=2,
        cols=4,
        effective_slots=128,
        partition_rows=1,
        matrix_value_bound=7,
        max_row_nnz=4,
        reserved_slack_beta=0.0,
        segment_width=128,
    )

    accounting = account_strong_transition(advance_strong_publication(state, window))
    plan = accounting.query_plan

    assert plan is not None
    assert plan.returned_share_count == 3
    assert plan.random_route_count == 2
    assert plan.dummy_route_count == 1
    assert accounting.metrics.blinding_mask_ciphertexts == 5 * plan.random_route_count
    assert accounting.metrics.blinding_dummy_ciphertexts == 5 * plan.dummy_route_count
    assert [route.kind for route in plan.f1m_routes].count("random-zero-sum") == 2
    assert [route.kind for route in plan.f1m_routes].count("encrypted-zero-dummy") == 1


def test_strong_update_only_window_has_no_query_or_rotation_accounting() -> None:
    result = simulate_strong_reference(
        [
            PublicationWindow(
                index=0,
                start_time=0.0,
                end_time=0.0,
                updates=(NetUpdate(row=0, col=1, before=0, after=3),),
                query_count=0,
                reason="version",
            ),
            PublicationWindow(
                index=1,
                start_time=1.0,
                end_time=1.0,
                updates=(NetUpdate(row=0, col=2, before=0, after=4),),
                query_count=0,
                reason="version",
            ),
        ],
        {(0, 0): 1, (1, 0): 2},
        _config(),
        measure_from=1,
    )

    assert result.metrics.updates == 1
    assert result.metrics.update_ciphertexts == 1
    assert result.metrics.compaction_ciphertexts == 0
    assert result.metrics.ci_patch_entries == 1
    assert result.metrics.ci_full_sync_entries == 0
    assert result.metrics.metadata_units == 1
    assert result.metrics.queries == 0
    assert result.metrics.query_ciphertexts == 0
    assert result.metrics.relinearizations == 0
    assert result.metrics.blinding_encryptions == 0
    assert result.rotation_inventory.measured_counts_by_exact_index == ()
    assert result.rotation_inventory.required_indices == ()


def test_strong_simulation_freezes_c128_and_remains_unregistered() -> None:
    assert STRONG_REFERENCE_STRATEGY not in STRATEGIES
    assert STRONG_REFERENCE_STRATEGY not in {
        metrics.strategy for metrics in simulate([], {}, _config(), measure_from=0)
    }
    assert simulate_strong_reference([], {}, _config(), measure_from=0).metrics.strategy == (
        STRONG_REFERENCE_STRATEGY
    )
    with pytest.raises(ValueError, match="strategy"):
        simulate_targets(
            [],
            {},
            [SimulationTarget("strong", STRONG_REFERENCE_STRATEGY, _config())],  # type: ignore[arg-type]
            measure_from=0,
        )

    with pytest.raises(ValueError, match="segment_width"):
        simulate_strong_reference(
            [],
            {},
            _config(effective_slots=127),
            measure_from=0,
        )


def test_strong_rotation_requirements_include_unmeasured_warmup_query_dag() -> None:
    result = simulate_strong_reference(
        [
            PublicationWindow(
                index=0,
                start_time=0.0,
                end_time=0.0,
                updates=(NetUpdate(row=0, col=1, before=0, after=3),),
                query_count=1,
                reason="query",
            ),
            _window(index=1, queries=0),
        ],
        {(0, 0): 1, (1, 0): 2},
        _config(),
        measure_from=1,
    )

    assert result.metrics.queries == 0
    assert result.metrics.rotations == 0
    assert result.rotation_inventory.measured_counts_by_exact_index == ()
    assert result.rotation_inventory.required_indices == (1, 2, 4, 8, 16, 32, 64)
