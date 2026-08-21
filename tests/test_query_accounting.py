from __future__ import annotations

from dynamic_cssc.events import NetUpdate, PublicationWindow
from dynamic_cssc.metrics import StrategyMetrics, UnitCosts
from dynamic_cssc.simulator import SimulationConfig, simulate

QUERY_SIDE_FIELDS = (
    "query_ciphertexts",
    "result_ciphertexts",
    "cc_multiplications",
    "rotations",
    "additions",
    "plaintext_masks",
    "blinding_mask_ciphertexts",
    "blinding_encryptions",
    "blinding_additions",
    "decryptions",
    "client_merges",
    "mask_random_elements",
    "mask_mapped_elements",
    "client_reorder_elements",
)


def _config(**overrides: object) -> SimulationConfig:
    values: dict[str, object] = {
        "rows": 4,
        "cols": 8,
        "effective_slots": 8,
        "partition_rows": 2,
        "matrix_value_bound": 7,
        "max_row_nnz": 8,
        "reserved_slack_beta": 0.1,
        "periodic_repack_windows": 4,
        "packed_coo_segment_capacity": 8,
    }
    values.update(overrides)
    return SimulationConfig(**values)  # type: ignore[arg-type]


def _query_window(index: int, query_count: int) -> PublicationWindow:
    return PublicationWindow(
        index=index,
        start_time=float(index),
        end_time=float(index),
        updates=(),
        query_count=query_count,
        reason="query",
    )


def test_update_only_window_has_zero_query_side_accounting() -> None:
    window = PublicationWindow(
        index=0,
        start_time=0.0,
        end_time=0.1,
        updates=(NetUpdate(row=0, col=0, before=1, after=2),),
        query_count=0,
        reason="end-of-stream",
    )

    metrics = simulate([window], {(0, 0): 1}, _config())

    assert metrics
    for item in metrics:
        assert item.queries == 0
        assert {field: getattr(item, field) for field in QUERY_SIDE_FIELDS} == {
            field: 0 for field in QUERY_SIDE_FIELDS
        }


def test_update_amplification_excludes_query_blinding_masks() -> None:
    metrics = StrategyMetrics(
        "example",
        "reference",
        updates=5,
        update_ciphertexts=3,
        compaction_ciphertexts=2,
        blinding_mask_ciphertexts=7,
    )

    assert metrics.update_ct_equivalents() == 1.0


def test_query_side_counts_scale_with_queries_and_accumulate() -> None:
    initial = {(0, 0): 1}
    one_query = {
        item.strategy: item for item in simulate([_query_window(0, 1)], initial, _config())
    }
    four_queries = {
        item.strategy: item
        for item in simulate(
            [_query_window(0, 1), _query_window(1, 3)], initial, _config()
        )
    }

    assert one_query.keys() == four_queries.keys()
    for strategy, one in one_query.items():
        four = four_queries[strategy]
        assert four.queries == 4
        for field in QUERY_SIDE_FIELDS:
            assert getattr(four, field) == 4 * getattr(one, field)


def test_cssc_query_counts_reduction_adds_masks_and_cross_chunk_merge() -> None:
    initial = {
        (row, col): 1
        for row, width in enumerate((4, 2, 1))
        for col in range(width)
    }
    config = _config(rows=3, effective_slots=8, partition_rows=3)

    metrics = {
        item.strategy: item
        for item in simulate([_query_window(0, 2)], initial, config)
    }
    padding = metrics["PaddingReuse-CSSC"]

    # The two CSSC chunks have widths 2 and 2: two rotate-and-add steps,
    # two non-identity lane masks, then one addition to merge the chunks.
    assert padding.rotations == 4
    assert padding.additions == 6
    assert padding.plaintext_masks == 4


def test_cssc_query_omits_identity_lane_mask() -> None:
    initial = {(row, 0): 1 for row in range(4)}
    config = _config(
        rows=4,
        cols=4,
        effective_slots=4,
        partition_rows=4,
        max_row_nnz=4,
        packed_coo_segment_capacity=4,
    )

    metrics = {
        item.strategy: item
        for item in simulate([_query_window(0, 1)], initial, config)
    }
    padding = metrics["PaddingReuse-CSSC"]

    assert padding.rotations == 0
    assert padding.additions == 0
    assert padding.plaintext_masks == 0


def test_mini_cssc_accumulates_base_and_delta_query_operations() -> None:
    initial = {
        (row, col): 1
        for row, width in enumerate((4, 2, 1))
        for col in range(width)
    }
    window = PublicationWindow(
        index=0,
        start_time=0.0,
        end_time=0.0,
        updates=(NetUpdate(row=0, col=4, before=0, after=1),),
        query_count=3,
        reason="query",
    )
    config = _config(
        rows=3,
        cols=5,
        effective_slots=8,
        partition_rows=3,
        max_row_nnz=5,
        reserved_slack_beta=0.0,
    )

    metrics = {item.strategy: item for item in simulate([window], initial, config)}
    mini = metrics["Mini-CSSC-Delta"]

    # Base contributes (2 rotations, 3 adds, 2 masks); the one-row delta
    # contributes (0 rotations, 0 adds, 1 non-identity mask), all per query.
    assert mini.query_ciphertexts == 9
    assert mini.rotations == 6
    assert mini.additions == 9
    assert mini.plaintext_masks == 9


def test_report_costs_use_query_denominator_and_charge_masks_to_query() -> None:
    metrics = StrategyMetrics(
        "example",
        "reference",
        queries=2,
        update_encryptions=3,
        query_ciphertexts=4,
        cc_multiplications=2,
        blinding_encryptions=6,
        blinding_additions=8,
    )
    costs = UnitCosts()

    record = metrics.to_record(costs)

    assert record["predicted_update_time"] == 24.0
    assert record["predicted_query_time"] == 136.0
    assert record["predicted_query_time_per_query"] == 68.0
    assert record["predicted_normalized_time"] == 160.0


def test_delta_masks_only_output_blocks_that_overlap_logical_rows() -> None:
    initial = {(row, 0): 1 for row in range(4)}
    window = PublicationWindow(
        index=0,
        start_time=0.0,
        end_time=0.0,
        updates=(NetUpdate(row=0, col=1, before=0, after=1),),
        query_count=1,
        reason="query",
    )
    config = _config(
        rows=4,
        cols=4,
        effective_slots=4,
        partition_rows=2,
        max_row_nnz=4,
        reserved_slack_beta=0.0,
        packed_coo_segment_capacity=4,
    )

    metrics = {item.strategy: item for item in simulate([window], initial, config)}

    mini = metrics["Mini-CSSC-Delta"]
    assert mini.result_ciphertexts == 3
    assert mini.blinding_mask_ciphertexts == 2
    assert mini.blinding_encryptions == 2
    assert mini.blinding_additions == 2
    assert mini.mask_random_elements == 1
    assert mini.mask_mapped_elements == 2
    assert mini.client_reorder_elements == 5
    assert mini.client_merges == 1
    assert metrics["PaddingReuse-CSSC"].blinding_mask_ciphertexts == 0


def test_simulator_returns_only_fixed_metrics_and_leaves_oracle_to_runner() -> None:
    metrics = simulate([_query_window(0, 1)], {(0, 0): 1}, _config())
    by_name = {item.strategy: item for item in metrics}

    assert "Hybrid-Selector-Proxy" not in by_name
    assert "BestFixed-Offline-Oracle" not in by_name
    assert set(by_name) == {
        "PaddingReuse-CSSC",
        "ReservedSlack-CSSC",
        "Mini-CSSC-Delta",
        "Packed-COO-HYB-Delta",
        "Strict-LocalRepack",
        "PeriodicRepack",
    }
    assert all(item.category == "reference" for item in metrics)
    assert all(item.source == "persistent-state-predicted" for item in metrics)
