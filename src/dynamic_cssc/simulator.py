from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from .events import PublicationWindow
from .metrics import StrategyMetrics
from .output_plan import analyze_output_plan
from .strategy_state import (
    STRATEGIES,
    StrategyKind,
    StrategyState,
    Transition,
    advance_publication,
    initialize_strategy,
)


@dataclass(frozen=True, slots=True)
class SimulationConfig:
    rows: int
    cols: int
    effective_slots: int
    partition_rows: int
    matrix_value_bound: int
    max_row_nnz: int
    reserved_slack_beta: float
    periodic_repack_windows: int
    packed_coo_segment_capacity: int


@dataclass(frozen=True, slots=True)
class SimulationTarget:
    run_id: str
    strategy: StrategyKind
    config: SimulationConfig


@dataclass(frozen=True, slots=True)
class SimulationResult:
    metrics: StrategyMetrics
    overflow_by_row: dict[int, int]


def _is_strict_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _strategy_options(config: SimulationConfig) -> dict[str, object]:
    return {
        "rows": config.rows,
        "cols": config.cols,
        "effective_slots": config.effective_slots,
        "partition_rows": config.partition_rows,
        "matrix_value_bound": config.matrix_value_bound,
        "max_row_nnz": config.max_row_nnz,
        "reserved_slack_beta": config.reserved_slack_beta,
        "periodic_repack_windows": config.periodic_repack_windows,
        "packed_coo_segment_capacity": config.packed_coo_segment_capacity,
    }


def _metrics_for(transition: Transition) -> StrategyMetrics:
    """Adapt one successful persistent transition to the fixed accounting schema."""

    state = transition.state
    facts = transition.facts
    value_updates = facts.value_patch_chunks
    rebuilt = facts.rebuilt_ciphertexts
    delta_rebuilt = facts.delta_rebuilt_ciphertexts
    metrics = StrategyMetrics(
        strategy=state.strategy,
        category="reference",
        windows=1,
        queries=facts.query_count,
        updates=facts.updates,
        update_encryptions=value_updates + rebuilt + delta_rebuilt,
        update_ciphertexts=value_updates + delta_rebuilt,
        compaction_ciphertexts=rebuilt,
        metadata_units=facts.ci_patch_entries + facts.ci_full_sync_entries,
        overflow_updates=facts.overflow,
        absorbed_updates=(
            facts.absorbed_tombstone
            + facts.absorbed_natural_padding
            + facts.absorbed_reserved
        ),
        source="persistent-state-predicted",
    )
    queries = facts.query_count
    if queries == 0:
        return metrics

    query_ciphertexts = 0
    cc_multiplications = 0
    rotations = 0
    additions = 0
    plaintext_masks = 0
    components = (state.base,) if state.delta is None else (state.base, state.delta)
    for component in components:
        for block in component.blocks:
            if not block.chunks:
                continue
            query_ciphertexts += len(block.chunks)
            cc_multiplications += len(block.chunks)
            block_rotations = sum(
                chunk.aggregation_rotations_proxy for chunk in block.chunks
            )
            rotations += block_rotations
            additions += block_rotations + len(block.chunks) - 1
            plaintext_masks += sum(
                chunk.height < component.layout_spec.effective_slots
                for chunk in block.chunks
            )

    if state.strategy == "Packed-COO-Client-Lane-Delta":
        active_segments = sum(
            any(entry is not None and entry.value != 0 for entry in segment.entries)
            for segment in state.coo_segments
        )
        query_ciphertexts += active_segments
        cc_multiplications += active_segments

    analysis = analyze_output_plan(transition.output_plan)
    metrics.query_ciphertexts = queries * query_ciphertexts
    metrics.cc_multiplications = queries * cc_multiplications
    metrics.rotations = queries * rotations
    metrics.additions = queries * additions
    metrics.plaintext_masks = queries * plaintext_masks
    metrics.result_ciphertexts = queries * analysis.result_ciphertexts
    metrics.blinding_mask_ciphertexts = queries * analysis.masked_result_ciphertexts
    metrics.blinding_encryptions = queries * analysis.masked_result_ciphertexts
    metrics.blinding_additions = queries * analysis.masked_result_ciphertexts
    metrics.decryptions = queries * analysis.result_ciphertexts
    metrics.client_merges = queries * analysis.client_modular_additions
    metrics.mask_random_elements = queries * analysis.mask_random_elements
    metrics.mask_mapped_elements = queries * analysis.mask_mapped_elements
    metrics.client_reorder_elements = queries * analysis.client_reorder_elements
    return metrics


def simulate_targets(
    windows: list[PublicationWindow],
    initial: dict[tuple[int, int], int],
    targets: list[SimulationTarget],
    *,
    measure_from: int,
) -> dict[str, SimulationResult]:
    """Replay independent target snapshots and aggregate one positional suffix."""

    if not isinstance(windows, list):
        raise ValueError("windows must be a list")
    if any(not isinstance(window, PublicationWindow) for window in windows):
        raise ValueError("windows must contain PublicationWindow values")
    if not isinstance(initial, dict):
        raise ValueError("initial must be a coordinate-to-value dict")
    if not isinstance(targets, list):
        raise ValueError("targets must be a list")
    if not targets:
        raise ValueError("targets must not be empty")
    if (
        not _is_strict_int(measure_from)
        or measure_from < 0
        or measure_from > len(windows)
    ):
        raise ValueError("measure_from must be a strict integer in [0, len(windows)]")

    run_ids: set[str] = set()
    for target in targets:
        if not isinstance(target, SimulationTarget):
            raise ValueError("targets must contain SimulationTarget values")
        if not isinstance(target.run_id, str) or not target.run_id:
            raise ValueError("target run_id must be a nonempty string")
        if target.run_id in run_ids:
            raise ValueError("target run_id values must be unique")
        if target.strategy not in STRATEGIES:
            raise ValueError(f"target strategy must be one of {STRATEGIES}")
        if not isinstance(target.config, SimulationConfig):
            raise ValueError("target config must be a SimulationConfig")
        run_ids.add(target.run_id)

    states: dict[str, StrategyState] = {}
    metrics_by_run: dict[str, StrategyMetrics] = {}
    overflow_by_run: dict[str, Counter[int]] = {}
    for target in targets:
        states[target.run_id] = initialize_strategy(
            target.strategy,
            initial,
            **_strategy_options(target.config),
        )
        metrics_by_run[target.run_id] = StrategyMetrics(
            strategy=target.strategy,
            category="reference",
            source="persistent-state-predicted",
        )
        overflow_by_run[target.run_id] = Counter()

    for position, window in enumerate(windows):
        transitions: dict[str, Transition] = {}
        for target in targets:
            transition = advance_publication(states[target.run_id], window)
            transitions[target.run_id] = transition
        logical_states = [transition.state.logical for transition in transitions.values()]
        if any(logical != logical_states[0] for logical in logical_states[1:]):
            raise AssertionError("all targets must publish the same logical state per window")
        if position >= measure_from:
            for run_id, transition in transitions.items():
                metrics_by_run[run_id].merge(_metrics_for(transition))
                overflow_by_run[run_id].update(transition.facts.overflow_rows)
        states = {
            run_id: transition.state for run_id, transition in transitions.items()
        }

    return {
        target.run_id: SimulationResult(
            metrics=metrics_by_run[target.run_id],
            overflow_by_row=dict(sorted(overflow_by_run[target.run_id].items())),
        )
        for target in targets
    }


def simulate(
    windows: list[PublicationWindow],
    initial_state: dict[tuple[int, int], int],
    config: SimulationConfig,
    *,
    measure_from: int = 0,
) -> list[StrategyMetrics]:
    """Replay the canonical fixed-strategy set through the target seam once."""

    if not isinstance(config, SimulationConfig):
        raise ValueError("config must be a SimulationConfig")
    results = simulate_targets(
        windows,
        initial_state,
        [
            SimulationTarget(
                run_id=strategy,
                strategy=strategy,
                config=config,
            )
            for strategy in STRATEGIES
        ],
        measure_from=measure_from,
    )
    return sorted(
        (result.metrics for result in results.values()),
        key=lambda metrics: metrics.strategy,
    )
