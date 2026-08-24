from __future__ import annotations

from collections import Counter
from dataclasses import replace
from inspect import Parameter, signature

import pytest

import dynamic_cssc.simulator as simulator_module
from dynamic_cssc.events import NetUpdate, PublicationWindow
from dynamic_cssc.simulator import (
    RotationInventory,
    SimulationConfig,
    SimulationTarget,
    simulate,
    simulate_targets,
)
from dynamic_cssc.strategy_state import STRATEGIES


def _window(
    *updates: NetUpdate,
    index: int,
    queries: int = 0,
) -> PublicationWindow:
    return PublicationWindow(
        index=index,
        start_time=float(index),
        end_time=float(index),
        updates=tuple(updates),
        query_count=queries,
        reason="query" if queries else "version",
    )


def _config(**overrides: object) -> SimulationConfig:
    values: dict[str, object] = {
        "rows": 2,
        "cols": 6,
        "effective_slots": 4,
        "partition_rows": 2,
        "matrix_value_bound": 7,
        "max_row_nnz": 6,
        "reserved_slack_beta": 0.0,
        "periodic_repack_windows": 3,
        "packed_coo_segment_capacity": 4,
    }
    values.update(overrides)
    return SimulationConfig(**values)  # type: ignore[arg-type]


def test_simulate_targets_owns_each_run_lifecycle_and_measures_only_the_suffix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    targets = [
        SimulationTarget(f"candidate-{index}", "PaddingReuse-CSSC", _config())
        for index in range(13)
    ]
    windows = [_window(index=index, queries=1) for index in range(3)]
    initialized_state_ids: list[int] = []
    advanced_state_ids: list[int] = []
    real_initialize = simulator_module.initialize_strategy
    real_advance = simulator_module.advance_publication

    def counting_initialize(*args: object, **kwargs: object) -> object:
        state = real_initialize(*args, **kwargs)  # type: ignore[arg-type]
        initialized_state_ids.append(id(state))
        return state

    def counting_advance(*args: object, **kwargs: object) -> object:
        advanced_state_ids.append(id(args[0]))
        return real_advance(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(simulator_module, "initialize_strategy", counting_initialize)
    monkeypatch.setattr(simulator_module, "advance_publication", counting_advance)

    results = simulate_targets(
        windows,
        {(0, 0): 1},
        targets,
        measure_from=1,
    )

    assert list(results) == [target.run_id for target in targets]
    assert len(set(initialized_state_ids)) == 13
    assert Counter(advanced_state_ids) == Counter(
        {state_id: 3 for state_id in initialized_state_ids}
    )
    assert all(result.metrics.windows == 2 for result in results.values())
    assert all(result.metrics.queries == 2 for result in results.values())


def test_simulate_targets_rejects_duplicate_run_ids_before_initialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    targets = [
        SimulationTarget("duplicate", "PaddingReuse-CSSC", _config()),
        SimulationTarget("duplicate", "Mini-CSSC-Delta", _config()),
    ]

    def unexpected_initialize(*args: object, **kwargs: object) -> object:
        raise AssertionError("duplicate targets must fail before initialization")

    monkeypatch.setattr(
        simulator_module,
        "initialize_strategy",
        unexpected_initialize,
    )

    with pytest.raises(ValueError, match="run_id"):
        simulate_targets([], {(0, 0): 1}, targets, measure_from=0)


def test_simulate_targets_rejects_an_empty_target_list() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        simulate_targets([], {(0, 0): 1}, [], measure_from=0)


@pytest.mark.parametrize(
    ("measured", "required"),
    (
        (((2, 1), (1, 1)), (1, 2)),
        (((1, 1), (1, 2)), (1,)),
        (((1, 0),), (1,)),
        (((True, 1),), (1,)),
        (((2, 1),), (1,)),
        ((), (2, 1)),
        ((), (1, 1)),
    ),
)
def test_rotation_inventory_rejects_noncanonical_or_incomplete_values(
    measured: tuple[tuple[int, int], ...],
    required: tuple[int, ...],
) -> None:
    with pytest.raises(ValueError, match="rotation inventory"):
        RotationInventory(measured, required)


def test_simulation_config_requires_the_complete_canonical_schema() -> None:
    parameters = signature(SimulationConfig).parameters

    assert tuple(parameters) == (
        "rows",
        "cols",
        "effective_slots",
        "partition_rows",
        "matrix_value_bound",
        "max_row_nnz",
        "reserved_slack_beta",
        "periodic_repack_windows",
        "packed_coo_segment_capacity",
    )
    assert all(parameter.default is Parameter.empty for parameter in parameters.values())


def test_simulate_targets_exposes_sparse_measured_suffix_overflow_by_row() -> None:
    windows = [
        _window(NetUpdate(0, 1, 0, 2), index=0),
        _window(NetUpdate(1, 1, 0, 3), index=1),
        _window(NetUpdate(1, 2, 0, 4), index=2),
    ]
    config = _config(
        rows=2,
        cols=4,
        effective_slots=1,
        partition_rows=1,
        max_row_nnz=4,
        packed_coo_segment_capacity=1,
    )

    result = simulate_targets(
        windows,
        {(0, 0): 1, (1, 0): 1},
        [SimulationTarget("mini", "Mini-CSSC-Delta", config)],
        measure_from=1,
    )["mini"]

    assert result.metrics.windows == 2
    assert result.metrics.overflow_updates == 2
    assert result.overflow_by_row == {1: 2}


def test_packed_coo_target_excludes_overflow_absorbed_by_a_reused_segment_lane() -> None:
    config = _config(
        rows=2,
        cols=8,
        effective_slots=4,
        partition_rows=2,
        max_row_nnz=8,
        packed_coo_segment_capacity=2,
    )
    windows = [
        _window(
            NetUpdate(0, 4, 0, 5),
            NetUpdate(1, 4, 0, 6),
            index=0,
        ),
        _window(
            NetUpdate(0, 4, 5, 0),
            NetUpdate(1, 5, 0, 7),
            index=1,
        ),
    ]

    result = simulate_targets(
        windows,
        {(0, 0): 1, (0, 1): 2, (1, 0): 3, (1, 1): 4},
        [SimulationTarget("coo", "Packed-COO-Client-Lane-Delta", config)],
        measure_from=1,
    )["coo"]

    assert result.metrics.overflow_updates == 0
    assert result.overflow_by_row == {}


def test_simulate_targets_checks_same_window_logical_equality(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    targets = [
        SimulationTarget("padding", "PaddingReuse-CSSC", _config()),
        SimulationTarget("mini", "Mini-CSSC-Delta", _config()),
    ]
    real_advance = simulator_module.advance_publication
    call_count = 0

    def divergent_second_transition(*args: object, **kwargs: object) -> object:
        nonlocal call_count
        transition = real_advance(*args, **kwargs)  # type: ignore[arg-type]
        call_count += 1
        if call_count != 2:
            return transition
        return replace(
            transition,
            state=replace(
                transition.state,
                logical={**transition.state.logical, (0, 1): 2},
            ),
        )

    monkeypatch.setattr(
        simulator_module,
        "advance_publication",
        divergent_second_transition,
    )

    with pytest.raises(AssertionError, match="same logical state"):
        simulate_targets(
            [_window(index=0)],
            {(0, 0): 1},
            targets,
            measure_from=0,
        )


def test_query_accounting_fails_closed_on_a_canonically_different_output_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_advance = simulator_module.advance_publication

    def mismatched_output_plan(*args: object, **kwargs: object) -> object:
        transition = real_advance(*args, **kwargs)  # type: ignore[arg-type]
        first_share, *remaining_shares = transition.output_plan.shares
        altered_share = replace(
            first_share,
            slot_to_logical=tuple(
                (physical_slot, 1) for physical_slot, _logical in first_share.slot_to_logical
            ),
        )
        return replace(
            transition,
            output_plan=replace(
                transition.output_plan,
                shares=(altered_share, *remaining_shares),
            ),
        )

    monkeypatch.setattr(
        simulator_module,
        "advance_publication",
        mismatched_output_plan,
    )

    with pytest.raises(AssertionError, match="canonically match"):
        simulate_targets(
            [_window(index=0, queries=1)],
            {(0, 0): 1},
            [SimulationTarget("padding", "PaddingReuse-CSSC", _config())],
            measure_from=0,
        )


def test_positive_reserved_empty_row_lane_is_in_full_query_accounting() -> None:
    config = _config(
        rows=2,
        cols=4,
        effective_slots=4,
        partition_rows=2,
        max_row_nnz=4,
        reserved_slack_beta=0.5,
    )

    result = simulate_targets(
        [_window(index=0, queries=1)],
        {(0, 0): 1, (0, 1): 1},
        [SimulationTarget("reserved", "ReservedSlack-CSSC", config)],
        measure_from=0,
    )["reserved"]

    assert (
        result.metrics.query_ciphertexts,
        result.metrics.cc_multiplications,
        result.metrics.rotations,
        result.metrics.additions,
        result.metrics.plaintext_masks,
        result.metrics.result_ciphertexts,
        result.metrics.client_reorder_elements,
    ) == (2, 2, 1, 2, 2, 1, 2)


def test_each_ordinary_transition_compiles_all_active_sources_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
    real_compile = simulator_module.compile_query

    def recording_compile(components: tuple[object, ...], **kwargs: object) -> object:
        calls.append((components, kwargs))
        return real_compile(components, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(simulator_module, "compile_query", recording_compile)
    config = _config(
        rows=2,
        cols=4,
        effective_slots=4,
        partition_rows=2,
        max_row_nnz=4,
        reserved_slack_beta=0.0,
        packed_coo_segment_capacity=2,
    )

    simulate_targets(
        [_window(NetUpdate(0, 1, 0, 2), index=0, queries=1)],
        {(0, 0): 1, (1, 0): 1},
        [
            SimulationTarget("mini", "Mini-CSSC-Delta", config),
            SimulationTarget("coo", "Packed-COO-Client-Lane-Delta", config),
        ],
        measure_from=0,
    )

    assert len(calls) == 2
    mini_call = next(call for call in calls if len(call[0]) == 2)
    coo_call = next(call for call in calls if call[1]["client_lane_segments"])
    assert mini_call[1] == {
        "client_lane_segments": (),
        "f1m_policy": "overlap-only",
    }
    assert len(coo_call[0]) == 1
    assert len(coo_call[1]["client_lane_segments"]) == 1  # type: ignore[arg-type]
    assert coo_call[1]["f1m_policy"] == "overlap-only"


def test_simulate_advances_warmup_state_but_aggregates_only_the_measured_suffix() -> None:
    windows = [
        _window(NetUpdate(0, 1, 0, 2), index=0, queries=5),
        _window(NetUpdate(0, 1, 2, 3), index=1, queries=2),
    ]

    metrics = simulate(
        windows,
        {(0, 0): 1},
        _config(),
        measure_from=1,
    )

    assert {item.strategy for item in metrics} == set(STRATEGIES)
    assert all(item.windows == 1 for item in metrics)
    assert all(item.queries == 2 for item in metrics)
    assert all(item.updates == 1 for item in metrics)
    assert "BestFixed-Offline-Oracle" not in {item.strategy for item in metrics}


def test_rotation_inventory_counts_only_suffix_queries_but_requires_warmup_dags() -> None:
    result = simulate_targets(
        [
            _window(index=0, queries=3),
            _window(index=1, queries=2),
        ],
        {(0, 0): 1, (0, 1): 2, (0, 2): 3},
        [
            SimulationTarget(
                "padding",
                "PaddingReuse-CSSC",
                _config(rows=1, cols=3, partition_rows=1, max_row_nnz=3),
            )
        ],
        measure_from=1,
    )["padding"]

    assert result.metrics.queries == 2
    assert result.rotation_inventory.measured_counts_by_exact_index == ((1, 2), (2, 2))
    assert result.rotation_inventory.required_indices == (1, 2)


def test_packed_coo_query_accounting_uses_client_lane_outputs() -> None:
    window = _window(
        NetUpdate(0, 4, 0, 5),
        NetUpdate(1, 4, 0, 6),
        NetUpdate(0, 5, 0, 7),
        index=0,
        queries=2,
    )

    metrics = {
        item.strategy: item
        for item in simulate(
            [window],
            {(0, 0): 1, (1, 0): 2},
            _config(effective_slots=3, packed_coo_segment_capacity=3),
        )
    }["Packed-COO-Client-Lane-Delta"]

    assert (
        metrics.query_ciphertexts,
        metrics.cc_multiplications,
        metrics.rotations,
        metrics.additions,
        metrics.plaintext_masks,
    ) == (4, 4, 0, 0, 2)
    assert (
        metrics.result_ciphertexts,
        metrics.blinding_mask_ciphertexts,
        metrics.client_reorder_elements,
        metrics.client_merges,
        metrics.mask_random_elements,
        metrics.mask_mapped_elements,
    ) == (4, 4, 10, 6, 6, 10)


def test_transition_facts_map_to_maintenance_metrics_without_double_counting() -> None:
    window = _window(NetUpdate(0, 1, 0, 2), index=0)
    metrics = {
        item.strategy: item
        for item in simulate(
            [window],
            {(0, 0): 1},
            _config(
                rows=1,
                cols=3,
                effective_slots=1,
                partition_rows=1,
                max_row_nnz=3,
                packed_coo_segment_capacity=1,
            ),
        )
    }

    mini = metrics["Mini-CSSC-Delta"]
    assert (
        mini.update_encryptions,
        mini.update_ciphertexts,
        mini.compaction_ciphertexts,
        mini.ci_patch_entries,
        mini.ci_full_sync_entries,
        mini.metadata_units,
        mini.absorbed_updates,
        mini.overflow_updates,
    ) == (1, 1, 0, 0, 1, 1, 0, 1)
    padding = metrics["PaddingReuse-CSSC"]
    assert (
        padding.update_encryptions,
        padding.update_ciphertexts,
        padding.compaction_ciphertexts,
        padding.ci_patch_entries,
        padding.ci_full_sync_entries,
        padding.metadata_units,
        padding.absorbed_updates,
        padding.overflow_updates,
    ) == (2, 0, 2, 0, 2, 2, 0, 1)


def test_cloud_additions_do_not_merge_disjoint_horizontal_output_blocks() -> None:
    initial = {(row, 0): 1 for row in range(4)}

    metrics = {
        item.strategy: item
        for item in simulate(
            [_window(index=0, queries=1)],
            initial,
            _config(
                rows=4,
                cols=2,
                effective_slots=2,
                partition_rows=2,
                packed_coo_segment_capacity=2,
            ),
        )
    }["PaddingReuse-CSSC"]

    assert metrics.query_ciphertexts == 2
    assert metrics.cc_multiplications == 2
    assert metrics.rotations == 0
    assert metrics.additions == 0
    assert metrics.plaintext_masks == 0


def test_packed_coo_cloud_operations_ignore_logical_rowmap_labels() -> None:
    config = _config(
        cols=4,
        effective_slots=4,
        partition_rows=2,
        packed_coo_segment_capacity=2,
    )
    left = {
        item.strategy: item
        for item in simulate(
            [_window(NetUpdate(0, 2, 0, 2), index=0, queries=1)],
            {(0, 0): 1, (0, 1): 1, (1, 0): 1},
            config,
        )
    }["Packed-COO-Client-Lane-Delta"]
    right = {
        item.strategy: item
        for item in simulate(
            [_window(NetUpdate(1, 2, 0, 2), index=0, queries=1)],
            {(0, 0): 1, (1, 0): 1, (1, 1): 1},
            config,
        )
    }["Packed-COO-Client-Lane-Delta"]

    cloud_fields = (
        "query_ciphertexts",
        "cc_multiplications",
        "rotations",
        "additions",
        "plaintext_masks",
    )
    assert tuple(getattr(left, field) for field in cloud_fields) == tuple(
        getattr(right, field) for field in cloud_fields
    )


@pytest.mark.parametrize("measure_from", (True, -1, 2))
def test_measure_from_rejects_bool_negative_and_out_of_range(
    measure_from: object,
) -> None:
    with pytest.raises(ValueError, match="measure_from"):
        simulate(
            [_window(index=0)],
            {(0, 0): 1},
            _config(),
            measure_from=measure_from,  # type: ignore[arg-type]
        )


def test_simulate_rejects_a_non_mapping_initial_state_cleanly() -> None:
    with pytest.raises(ValueError, match="initial"):
        simulate([], None, _config())  # type: ignore[arg-type]
