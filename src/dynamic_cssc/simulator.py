from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from .cloud_execution_plan import CloudProgram, Rotate
from .events import PublicationWindow
from .metrics import StrategyMetrics
from .output_plan import canonical_output_plan_payload
from .query_compiler import compile_query
from .strategy_state import (
    STRATEGIES,
    StrategyKind,
    StrategyState,
    StrongTransition,
    Transition,
    advance_publication,
    advance_strong_publication,
    initialize_strategy,
    initialize_strong_strategy,
)

STRONG_REFERENCE_STRATEGY = "Packed-COO-Cloud-Segmented-Delta"
STRONG_REFERENCE_SEGMENT_WIDTH = 128


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
class RotationInventory:
    measured_counts_by_exact_index: tuple[tuple[int, int], ...] = ()
    required_indices: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        invalid = ValueError("rotation inventory must be canonical and complete")
        if not isinstance(self.measured_counts_by_exact_index, tuple) or not isinstance(
            self.required_indices, tuple
        ):
            raise invalid
        measured_indices: list[int] = []
        for entry in self.measured_counts_by_exact_index:
            if not isinstance(entry, tuple) or len(entry) != 2:
                raise invalid
            index, count = entry
            if not _is_strict_int(index) or index == 0 or not _is_strict_int(count) or count <= 0:
                raise invalid
            measured_indices.append(index)
        if measured_indices != sorted(set(measured_indices)):
            raise invalid
        if any(not _is_strict_int(index) or index == 0 for index in self.required_indices):
            raise invalid
        if list(self.required_indices) != sorted(set(self.required_indices)):
            raise invalid
        if not set(measured_indices).issubset(self.required_indices):
            raise invalid


@dataclass(frozen=True, slots=True)
class SimulationResult:
    metrics: StrategyMetrics
    overflow_by_row: dict[int, int]
    rotation_inventory: RotationInventory = RotationInventory()


@dataclass(frozen=True, slots=True)
class _WindowAccounting:
    metrics: StrategyMetrics
    rotations_per_query: tuple[tuple[int, int], ...]


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


def _rotation_counts_for_program(program: CloudProgram) -> Counter[int]:
    return Counter(node.openfhe_index for node in program.nodes if isinstance(node, Rotate))


def _rotation_inventory(
    measured: Counter[int], required: set[int], metrics: StrategyMetrics
) -> RotationInventory:
    measured_items = tuple(sorted(measured.items()))
    if sum(count for _, count in measured_items) != metrics.rotations:
        raise AssertionError("measured rotation inventory must reconcile with metrics")
    return RotationInventory(measured_items, tuple(sorted(required)))


def _metrics_for(transition: Transition) -> _WindowAccounting:
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
        ci_patch_entries=facts.ci_patch_entries,
        ci_full_sync_entries=facts.ci_full_sync_entries,
        metadata_units=facts.ci_patch_entries + facts.ci_full_sync_entries,
        overflow_updates=facts.overflow,
        absorbed_updates=(
            facts.absorbed_tombstone + facts.absorbed_natural_padding + facts.absorbed_reserved
        ),
        source="persistent-state-predicted",
    )
    queries = facts.query_count
    if queries == 0:
        return _WindowAccounting(metrics, ())

    components = (state.base,) if state.delta is None else (state.base, state.delta)
    compiled = compile_query(
        components,
        client_lane_segments=state.coo_segments,
        f1m_policy="overlap-only",
    )
    if canonical_output_plan_payload(compiled.output_plan) != canonical_output_plan_payload(
        transition.output_plan
    ):
        raise AssertionError("compiled OutputPlan must canonically match the transition OutputPlan")

    counts = compiled.cloud_counts
    analysis = compiled.output_analysis
    query_ciphertexts = dict(counts.ciphertext_inputs_by_role).get("query", 0)
    if not (
        query_ciphertexts == counts.multiply_ciphertexts == counts.relinearizations
        and counts.returned_ciphertexts == analysis.result_ciphertexts
        and counts.add_f1m_masks == analysis.masked_result_ciphertexts
    ):
        raise AssertionError("ordinary typed query accounting must be closed")
    metrics.query_ciphertexts = queries * query_ciphertexts
    metrics.cc_multiplications = queries * counts.multiply_ciphertexts
    metrics.relinearizations = queries * counts.relinearizations
    metrics.rotations = queries * counts.rotations
    metrics.additions = queries * counts.add_ciphertexts
    metrics.plaintext_masks = queries * counts.multiply_plaintext_masks
    metrics.result_ciphertexts = queries * counts.returned_ciphertexts
    metrics.blinding_mask_ciphertexts = queries * counts.add_f1m_masks
    metrics.blinding_encryptions = queries * counts.add_f1m_masks
    metrics.blinding_additions = queries * counts.add_f1m_masks
    metrics.decryptions = queries * counts.returned_ciphertexts
    metrics.client_merges = queries * analysis.client_modular_additions
    metrics.mask_random_elements = queries * analysis.mask_random_elements
    metrics.mask_mapped_elements = queries * analysis.mask_mapped_elements
    metrics.client_reorder_elements = queries * analysis.client_reorder_elements
    rotations = _rotation_counts_for_program(compiled.cloud_plan.program)
    if sum(rotations.values()) != counts.rotations:
        raise AssertionError("exact rotation counts must reconcile with the query DAG")
    return _WindowAccounting(metrics, tuple(sorted(rotations.items())))


def _strong_metrics_for(transition: StrongTransition) -> _WindowAccounting:
    """Adapt one strong transition and its actual query DAG to accounting metrics."""

    facts = transition.facts
    if facts.rebuilt_ciphertexts != 0:
        raise AssertionError("the frozen strong policy must not compact or rebuild the base")
    metrics = StrategyMetrics(
        strategy=STRONG_REFERENCE_STRATEGY,
        category="reference",
        windows=1,
        queries=facts.query_count,
        updates=facts.updates,
        update_encryptions=facts.value_patch_chunks + facts.delta_rebuilt_ciphertexts,
        update_ciphertexts=facts.value_patch_chunks + facts.delta_rebuilt_ciphertexts,
        compaction_ciphertexts=0,
        ci_patch_entries=facts.ci_patch_entries,
        ci_full_sync_entries=facts.ci_full_sync_entries,
        metadata_units=facts.ci_patch_entries + facts.ci_full_sync_entries,
        overflow_updates=facts.overflow,
        absorbed_updates=(
            facts.absorbed_tombstone + facts.absorbed_natural_padding + facts.absorbed_reserved
        ),
        source="persistent-state-predicted",
    )
    queries = facts.query_count
    if queries == 0:
        return _WindowAccounting(metrics, ())

    counts = transition.execution_bundle.cloud_counts
    analysis = transition.execution_bundle.output_analysis
    f1m = transition.execution_bundle.f1m_counts
    query_ciphertexts = dict(counts.ciphertext_inputs_by_role).get("query", 0)
    if not (
        query_ciphertexts == counts.multiply_ciphertexts == counts.relinearizations
        and counts.returned_ciphertexts == analysis.result_ciphertexts
        and counts.returned_ciphertexts == counts.add_f1m_masks
        and counts.returned_ciphertexts == f1m.ciphertext_additions
        and counts.returned_ciphertexts
        == f1m.random_zero_sum_ciphertexts + f1m.encrypted_zero_dummy_ciphertexts
        and f1m.random_zero_sum_ciphertexts == analysis.masked_result_ciphertexts
        and f1m.random_elements == analysis.mask_random_elements
    ):
        raise AssertionError("strong typed query and uniform F1M accounting must be closed")
    metrics.query_ciphertexts = queries * query_ciphertexts
    metrics.cc_multiplications = queries * counts.multiply_ciphertexts
    metrics.relinearizations = queries * counts.relinearizations
    metrics.rotations = queries * counts.rotations
    metrics.additions = queries * counts.add_ciphertexts
    metrics.plaintext_masks = queries * counts.multiply_plaintext_masks
    metrics.result_ciphertexts = queries * counts.returned_ciphertexts
    metrics.blinding_mask_ciphertexts = queries * f1m.random_zero_sum_ciphertexts
    metrics.blinding_dummy_ciphertexts = queries * f1m.encrypted_zero_dummy_ciphertexts
    metrics.blinding_encryptions = queries * (
        f1m.random_zero_sum_ciphertexts + f1m.encrypted_zero_dummy_ciphertexts
    )
    metrics.blinding_additions = queries * f1m.ciphertext_additions
    metrics.decryptions = queries * counts.returned_ciphertexts
    metrics.client_merges = queries * analysis.client_modular_additions
    metrics.mask_random_elements = queries * f1m.random_elements
    metrics.mask_mapped_elements = queries * analysis.mask_mapped_elements
    metrics.client_reorder_elements = queries * analysis.client_reorder_elements
    rotations = _rotation_counts_for_program(transition.execution_bundle.cloud_plan.program)
    if sum(rotations.values()) != counts.rotations:
        raise AssertionError("exact rotation counts must reconcile with the query DAG")
    return _WindowAccounting(metrics, tuple(sorted(rotations.items())))


def simulate_strong_reference(
    windows: list[PublicationWindow],
    initial: dict[tuple[int, int], int],
    config: SimulationConfig,
    *,
    measure_from: int,
) -> SimulationResult:
    """Replay the unregistered, frozen-c=128 strong reference independently."""

    if not isinstance(windows, list):
        raise ValueError("windows must be a list")
    if any(not isinstance(window, PublicationWindow) for window in windows):
        raise ValueError("windows must contain PublicationWindow values")
    if not isinstance(initial, dict):
        raise ValueError("initial must be a coordinate-to-value dict")
    if not isinstance(config, SimulationConfig):
        raise ValueError("config must be a SimulationConfig")
    if not _is_strict_int(measure_from) or measure_from < 0 or measure_from > len(windows):
        raise ValueError("measure_from must be a strict integer in [0, len(windows)]")

    state = initialize_strong_strategy(
        initial,
        rows=config.rows,
        cols=config.cols,
        effective_slots=config.effective_slots,
        partition_rows=config.partition_rows,
        matrix_value_bound=config.matrix_value_bound,
        max_row_nnz=config.max_row_nnz,
        reserved_slack_beta=0.0,
        segment_width=STRONG_REFERENCE_SEGMENT_WIDTH,
    )
    metrics = StrategyMetrics(
        strategy=STRONG_REFERENCE_STRATEGY,
        category="reference",
        source="persistent-state-predicted",
    )
    overflow_by_row: Counter[int] = Counter()
    measured_rotations: Counter[int] = Counter()
    required_indices: set[int] = set()
    for position, window in enumerate(windows):
        transition = advance_strong_publication(state, window)
        accounting = _strong_metrics_for(transition)
        if window.query_count:
            per_query_rotations = Counter(dict(accounting.rotations_per_query))
            required_indices.update(per_query_rotations)
            if position >= measure_from:
                measured_rotations.update(
                    {
                        index: count * window.query_count
                        for index, count in per_query_rotations.items()
                    }
                )
        if position >= measure_from:
            metrics.merge(accounting.metrics)
            overflow_by_row.update(transition.facts.overflow_rows)
        state = transition.state

    return SimulationResult(
        metrics=metrics,
        overflow_by_row=dict(sorted(overflow_by_row.items())),
        rotation_inventory=_rotation_inventory(measured_rotations, required_indices, metrics),
    )


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
    if not _is_strict_int(measure_from) or measure_from < 0 or measure_from > len(windows):
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
    measured_rotations_by_run: dict[str, Counter[int]] = {}
    required_indices_by_run: dict[str, set[int]] = {}
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
        measured_rotations_by_run[target.run_id] = Counter()
        required_indices_by_run[target.run_id] = set()

    for position, window in enumerate(windows):
        transitions: dict[str, Transition] = {}
        for target in targets:
            transition = advance_publication(states[target.run_id], window)
            transitions[target.run_id] = transition
        logical_states = [transition.state.logical for transition in transitions.values()]
        if any(logical != logical_states[0] for logical in logical_states[1:]):
            raise AssertionError("all targets must publish the same logical state per window")
        for run_id, transition in transitions.items():
            accounting = _metrics_for(transition)
            if transition.facts.query_count:
                per_query_rotations = Counter(dict(accounting.rotations_per_query))
                required_indices_by_run[run_id].update(per_query_rotations)
                if position >= measure_from:
                    measured_rotations_by_run[run_id].update(
                        {
                            index: count * transition.facts.query_count
                            for index, count in per_query_rotations.items()
                        }
                    )
            if position >= measure_from:
                metrics_by_run[run_id].merge(accounting.metrics)
                overflow_by_run[run_id].update(transition.facts.overflow_rows)
        states = {run_id: transition.state for run_id, transition in transitions.items()}

    return {
        target.run_id: SimulationResult(
            metrics=metrics_by_run[target.run_id],
            overflow_by_row=dict(sorted(overflow_by_run[target.run_id].items())),
            rotation_inventory=_rotation_inventory(
                measured_rotations_by_run[target.run_id],
                required_indices_by_run[target.run_id],
                metrics_by_run[target.run_id],
            ),
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
