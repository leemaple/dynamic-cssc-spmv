from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, replace
from typing import Literal

from .cloud_execution_plan import CloudProgram, Rotate
from .events import PublicationWindow
from .metrics import StrategyMetrics
from .output_plan import OutputPlan, canonical_output_plan_payload
from .query_compiler import CompiledQuery, compile_query
from .strategy_state import (
    STRATEGIES,
    StrategyKind,
    StrategyState,
    StrongStrategyState,
    StrongTransition,
    Transition,
    _assert_strong_strategy_invariants,
    _validated_predecessor,
    advance_publication,
    advance_strong_publication,
    assert_strategy_invariants,
    initialize_strategy,
    initialize_strong_strategy,
)
from .strong_execution import StrongExecutionBundle

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


@dataclass(slots=True)
class _CausalAccumulator:
    metrics: StrategyMetrics
    overflow_by_row: Counter[int]
    measured_rotations: Counter[int]
    required_indices: set[int]

    @classmethod
    def for_strategy(cls, strategy: str) -> _CausalAccumulator:
        return cls(
            metrics=StrategyMetrics(
                strategy=strategy,
                category="reference",
                source="persistent-state-predicted",
            ),
            overflow_by_row=Counter(),
            measured_rotations=Counter(),
            required_indices=set(),
        )

    def require(self, accounting: WindowAccounting) -> None:
        if accounting.metrics.queries:
            self.required_indices.update(dict(accounting.rotations_per_query))

    def measure(
        self,
        accounting: WindowAccounting,
        overflow_rows: tuple[int, ...],
    ) -> None:
        self.metrics.merge(accounting.metrics)
        self.overflow_by_row.update(overflow_rows)
        if accounting.metrics.queries:
            self.measured_rotations.update(
                {
                    index: count * accounting.metrics.queries
                    for index, count in accounting.rotations_per_query
                }
            )

    def result(self) -> SimulationResult:
        return SimulationResult(
            metrics=self.metrics,
            overflow_by_row=dict(sorted(self.overflow_by_row.items())),
            rotation_inventory=_rotation_inventory(
                self.measured_rotations,
                self.required_indices,
                self.metrics,
            ),
        )


@dataclass(frozen=True, slots=True)
class F1MRouteAccounting:
    """One per-query F1-M route class derived from the typed OutputPlan."""

    result_id: str
    result_ordinal: int
    f1m_route_ordinal: int
    component_id: str
    output_block_id: str
    kind: Literal["random-zero-sum", "encrypted-zero-dummy"]

    def __post_init__(self) -> None:
        for field in ("result_id", "component_id", "output_block_id"):
            value = getattr(self, field)
            if type(value) is not str or not value:
                raise ValueError(f"F1-M route {field} must be a nonempty string")
        for field in ("result_ordinal", "f1m_route_ordinal"):
            value = getattr(self, field)
            if type(value) is not int or value < 0:
                raise ValueError(f"F1-M route {field} must be a nonnegative strict integer")
        if self.kind not in {"random-zero-sum", "encrypted-zero-dummy"}:
            raise ValueError("F1-M route kind is not frozen")

    @property
    def category(self) -> str:
        return {
            "random-zero-sum": "query-f1m-random-mask-ciphertexts",
            "encrypted-zero-dummy": "query-f1m-encrypted-zero-dummy-ciphertexts",
        }[self.kind]

    def to_document(self) -> dict[str, str | int]:
        return {
            "category": self.category,
            "component_id": self.component_id,
            "f1m_route_ordinal": self.f1m_route_ordinal,
            "f1m_kind": self.kind,
            "output_block_id": self.output_block_id,
            "result_id": self.result_id,
            "result_ordinal": self.result_ordinal,
        }


@dataclass(frozen=True, slots=True)
class QueryPlanAccounting:
    """Compact deterministic identity and F1-M cardinality of one query DAG."""

    version_id: str
    cloud_program_digest: str
    output_plan_digest: str
    execution_binding_digest: str
    private_plan_digest: str
    returned_share_count: int
    f1m_routes: tuple[F1MRouteAccounting, ...]

    def __post_init__(self) -> None:
        if type(self.returned_share_count) is not int or self.returned_share_count < 0:
            raise ValueError("query-plan returned-share count must be nonnegative")
        if type(self.f1m_routes) is not tuple or any(
            type(route) is not F1MRouteAccounting for route in self.f1m_routes
        ):
            raise ValueError("query-plan F1-M routes must be an exact tuple")
        if tuple(route.f1m_route_ordinal for route in self.f1m_routes) != tuple(
            range(len(self.f1m_routes))
        ):
            raise ValueError("query-plan F1-M route ordinals must be contiguous from zero")
        result_ordinals = tuple(route.result_ordinal for route in self.f1m_routes)
        if (
            result_ordinals != tuple(sorted(result_ordinals))
            or len(set(result_ordinals)) != len(result_ordinals)
            or any(ordinal >= self.returned_share_count for ordinal in result_ordinals)
        ):
            raise ValueError("query-plan result ordinals are not a canonical subset")
        if len({route.result_id for route in self.f1m_routes}) != len(self.f1m_routes):
            raise ValueError("query-plan F1-M result identities are not unique")

    @property
    def random_route_count(self) -> int:
        return sum(route.kind == "random-zero-sum" for route in self.f1m_routes)

    @property
    def dummy_route_count(self) -> int:
        return sum(route.kind == "encrypted-zero-dummy" for route in self.f1m_routes)

    def to_document(self) -> dict[str, object]:
        return {
            "cloud_program_digest": self.cloud_program_digest,
            "dummy_route_count_per_query": self.dummy_route_count,
            "execution_binding_digest": self.execution_binding_digest,
            "f1m_routes": [route.to_document() for route in self.f1m_routes],
            "output_plan_digest": self.output_plan_digest,
            "private_plan_digest": self.private_plan_digest,
            "random_route_count_per_query": self.random_route_count,
            "returned_share_count_per_query": self.returned_share_count,
            "schema_version": "dynamic-cssc-window-query-plan-accounting-v2",
            "version_id": self.version_id,
        }


@dataclass(frozen=True, slots=True)
class WindowAccounting:
    """Exact work and query-plan cardinality for one persistent transition."""

    metrics: StrategyMetrics
    rotations_per_query: tuple[tuple[int, int], ...]
    query_plan: QueryPlanAccounting | None


_QUERY_LINEAR_METRIC_FIELDS = (
    "query_ciphertexts",
    "result_ciphertexts",
    "cc_multiplications",
    "relinearizations",
    "rotations",
    "additions",
    "plaintext_masks",
    "blinding_mask_ciphertexts",
    "blinding_dummy_ciphertexts",
    "blinding_encryptions",
    "blinding_additions",
    "decryptions",
    "client_merges",
    "mask_random_elements",
    "mask_mapped_elements",
    "client_reorder_elements",
)


@dataclass(frozen=True, slots=True)
class _QueryAccountingTemplate:
    metric_counts_per_query: tuple[tuple[str, int], ...]
    rotations_per_query: tuple[tuple[int, int], ...]


def _query_shape(transition: Transition | StrongTransition) -> tuple[object, ...]:
    state = transition.state
    components = (
        (state.base,)
        if isinstance(state, StrongStrategyState) or state.delta is None
        else (state.base, state.delta)
    )
    component_shape = tuple(
        tuple(
            tuple((chunk.width, chunk.height) for chunk in block.chunks)
            for block in component.blocks
        )
        for component in components
    )
    output_shape = tuple(
        (share.component_id, share.output_block_id, share.slot_to_logical)
        for share in transition.output_plan.shares
    )
    return (
        transition.output_plan.logical_output_size,
        transition.output_plan.slot_count,
        component_shape,
        output_shape,
    )


def _query_template(accounting: WindowAccounting) -> _QueryAccountingTemplate:
    queries = accounting.metrics.queries
    if queries <= 0:
        raise AssertionError("query templates require a query-bearing accounting record")
    counts: list[tuple[str, int]] = []
    for field in _QUERY_LINEAR_METRIC_FIELDS:
        value = getattr(accounting.metrics, field)
        if type(value) is not int or value % queries:
            raise AssertionError("query accounting must be exactly linear in query count")
        counts.append((field, value // queries))
    return _QueryAccountingTemplate(tuple(counts), accounting.rotations_per_query)


def _apply_query_template(
    accounting: WindowAccounting,
    template: _QueryAccountingTemplate,
    queries: int,
) -> WindowAccounting:
    accounting.metrics.queries = queries
    for field, per_query in template.metric_counts_per_query:
        setattr(accounting.metrics, field, per_query * queries)
    return WindowAccounting(
        accounting.metrics,
        template.rotations_per_query,
        None,
    )


def _cached_ordinary_accounting(
    transition: Transition,
    cache: dict[tuple[object, ...], _QueryAccountingTemplate],
) -> WindowAccounting:
    queries = transition.facts.query_count
    if queries == 0:
        return account_transition(transition)
    shape = _query_shape(transition)
    template = cache.get(shape)
    if template is None:
        accounting = account_transition(transition)
        cache[shape] = _query_template(accounting)
        return accounting
    zero_query = replace(
        transition,
        facts=replace(transition.facts, query_count=0),
    )
    return _apply_query_template(account_transition(zero_query), template, queries)


def _cached_strong_accounting(
    transition: StrongTransition,
    cache: dict[tuple[object, ...], _QueryAccountingTemplate],
) -> WindowAccounting:
    queries = transition.facts.query_count
    if queries == 0:
        return account_strong_transition(transition)
    shape = _query_shape(transition)
    template = cache.get(shape)
    if template is None:
        accounting = account_strong_transition(transition)
        cache[shape] = _query_template(accounting)
        return accounting
    zero_query = replace(
        transition,
        facts=replace(transition.facts, query_count=0),
    )
    return _apply_query_template(account_strong_transition(zero_query), template, queries)


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


def _masked_output_share_ids(output_plan: OutputPlan) -> frozenset[tuple[str, str]]:
    multiplicity: Counter[int] = Counter()
    for share in output_plan.shares:
        for _slot, logical_coordinate in share.slot_to_logical:
            multiplicity[logical_coordinate] += 1
    return frozenset(
        (share.component_id, share.output_block_id)
        for share in output_plan.shares
        if any(multiplicity[logical] > 1 for _slot, logical in share.slot_to_logical)
    )


def account_transition(transition: Transition) -> WindowAccounting:
    """Adapt one successful persistent transition to the fixed accounting schema."""

    accounting, _compiled = account_transition_with_compiled(transition)
    return accounting


def account_transition_with_compiled(
    transition: Transition,
) -> tuple[WindowAccounting, CompiledQuery | None]:
    """Return ordinary accounting plus its exact query-bearing compilation.

    The second value is a streaming-only carrier.  It is absent for a zero-query
    window and grants no execution or publication authority.
    """

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
        return WindowAccounting(metrics, (), None), None

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
    f1m_result_routes = tuple(
        (result_ordinal, route)
        for result_ordinal, route in enumerate(compiled.result_routes)
        if route.f1m_ciphertext_id is not None
    )
    routes = tuple(
        F1MRouteAccounting(
            result_id=route.result_id,
            result_ordinal=result_ordinal,
            f1m_route_ordinal=f1m_route_ordinal,
            component_id=route.component_id,
            output_block_id=route.output_block_id,
            kind="random-zero-sum",
        )
        for f1m_route_ordinal, (result_ordinal, route) in enumerate(f1m_result_routes)
    )
    if len(routes) * queries != metrics.blinding_mask_ciphertexts:
        raise AssertionError("ordinary F1-M route classes must reconcile with metrics")
    return (
        WindowAccounting(
            metrics,
            tuple(sorted(rotations.items())),
            QueryPlanAccounting(
                version_id=compiled.cloud_plan.binding.version_id,
                cloud_program_digest=compiled.cloud_program_digest,
                output_plan_digest=compiled.output_plan_digest,
                execution_binding_digest=compiled.execution_binding_digest,
                private_plan_digest=compiled.private_plan_digest,
                returned_share_count=len(compiled.result_routes),
                f1m_routes=routes,
            ),
        ),
        compiled,
    )


def account_strong_transition(transition: StrongTransition) -> WindowAccounting:
    """Adapt one strong transition and its actual query DAG to accounting metrics."""

    accounting, _bundle = account_strong_transition_with_bundle(transition)
    return accounting


def account_strong_transition_with_bundle(
    transition: StrongTransition,
) -> tuple[WindowAccounting, StrongExecutionBundle | None]:
    """Return strong accounting plus its exact query-bearing execution bundle.

    The second value is a streaming-only carrier.  It is absent for a zero-query
    window and grants no execution or publication authority.
    """

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
        return WindowAccounting(metrics, (), None), None

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
    masked_share_ids = _masked_output_share_ids(transition.execution_bundle.output_plan)
    routes = tuple(
        F1MRouteAccounting(
            result_id=route.result_id,
            result_ordinal=result_ordinal,
            f1m_route_ordinal=result_ordinal,
            component_id=route.component_id,
            output_block_id=route.output_block_id,
            kind=(
                "random-zero-sum"
                if route.output_share_id in masked_share_ids
                else "encrypted-zero-dummy"
            ),
        )
        for result_ordinal, route in enumerate(transition.execution_bundle.result_routes)
    )
    if (
        sum(route.kind == "random-zero-sum" for route in routes) * queries
        != metrics.blinding_mask_ciphertexts
        or sum(route.kind == "encrypted-zero-dummy" for route in routes) * queries
        != metrics.blinding_dummy_ciphertexts
    ):
        raise AssertionError("strong F1-M route classes must reconcile with metrics")
    return (
        WindowAccounting(
            metrics,
            tuple(sorted(rotations.items())),
            QueryPlanAccounting(
                version_id=transition.state.version_id,
                cloud_program_digest=transition.execution_bundle.cloud_program_digest,
                output_plan_digest=transition.execution_bundle.output_plan_digest,
                execution_binding_digest=(transition.execution_bundle.execution_binding_digest),
                private_plan_digest=transition.execution_bundle.private_plan_digest,
                returned_share_count=len(transition.execution_bundle.result_routes),
                f1m_routes=routes,
            ),
        ),
        transition.execution_bundle,
    )


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
    predecessor = _validated_predecessor(state)
    for position, window in enumerate(windows):
        transition = advance_strong_publication(
            state,
            window,
            _predecessor=predecessor,
        )
        accounting = account_strong_transition(transition)
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
        predecessor = _validated_predecessor(state)

    _assert_strong_strategy_invariants(state)

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
    predecessors = {}
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
        predecessors[target.run_id] = _validated_predecessor(states[target.run_id])

    for position, window in enumerate(windows):
        transitions: dict[str, Transition] = {}
        for target in targets:
            transition = advance_publication(
                states[target.run_id],
                window,
                _predecessor=predecessors[target.run_id],
            )
            transitions[target.run_id] = transition
        logical_states = [transition.state.logical for transition in transitions.values()]
        if any(logical != logical_states[0] for logical in logical_states[1:]):
            raise AssertionError("all targets must publish the same logical state per window")
        for run_id, transition in transitions.items():
            accounting = account_transition(transition)
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
        predecessors = {
            run_id: _validated_predecessor(transition.state)
            for run_id, transition in transitions.items()
        }

    for state in states.values():
        assert_strategy_invariants(state)

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


def simulate_targets_causal(
    windows: list[PublicationWindow],
    initial: dict[tuple[int, int], int],
    targets: list[SimulationTarget],
    *,
    warmup_end: int,
    tuning_end: int,
) -> tuple[dict[str, SimulationResult], dict[str, SimulationResult]]:
    """Replay fixed targets once and isolate tuning and held-out accumulators."""

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
        not _is_strict_int(warmup_end)
        or not _is_strict_int(tuning_end)
        or not 0 <= warmup_end < tuning_end < len(windows)
    ):
        raise ValueError("causal boundaries must satisfy 0 <= warmup < tuning < windows")

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
    tuning = {}
    held_out = {}
    predecessors = {}
    query_templates: dict[
        str, dict[tuple[object, ...], _QueryAccountingTemplate]
    ] = {}
    for target in targets:
        state = initialize_strategy(
            target.strategy,
            initial,
            **_strategy_options(target.config),
        )
        states[target.run_id] = state
        tuning[target.run_id] = _CausalAccumulator.for_strategy(target.strategy)
        held_out[target.run_id] = _CausalAccumulator.for_strategy(target.strategy)
        predecessors[target.run_id] = _validated_predecessor(state)
        query_templates[target.run_id] = {}

    for position, window in enumerate(windows):
        transitions: dict[str, Transition] = {}
        for target in targets:
            transition = advance_publication(
                states[target.run_id],
                window,
                _predecessor=predecessors[target.run_id],
            )
            transitions[target.run_id] = transition
        logical_states = [transition.state.logical for transition in transitions.values()]
        if any(logical != logical_states[0] for logical in logical_states[1:]):
            raise AssertionError("all targets must publish the same logical state per window")
        for run_id, transition in transitions.items():
            accounting = _cached_ordinary_accounting(
                transition,
                query_templates[run_id],
            )
            held_out[run_id].require(accounting)
            if position < tuning_end:
                tuning[run_id].require(accounting)
            if warmup_end <= position < tuning_end:
                tuning[run_id].measure(accounting, transition.facts.overflow_rows)
            elif position >= tuning_end:
                held_out[run_id].measure(accounting, transition.facts.overflow_rows)
        states = {run_id: transition.state for run_id, transition in transitions.items()}
        predecessors = {
            run_id: _validated_predecessor(transition.state)
            for run_id, transition in transitions.items()
        }

    for state in states.values():
        assert_strategy_invariants(state)
    return (
        {run_id: accumulator.result() for run_id, accumulator in tuning.items()},
        {run_id: accumulator.result() for run_id, accumulator in held_out.items()},
    )


def simulate_strong_reference_causal(
    windows: list[PublicationWindow],
    initial: dict[tuple[int, int], int],
    config: SimulationConfig,
    *,
    warmup_end: int,
    tuning_end: int,
) -> tuple[SimulationResult, SimulationResult]:
    """Replay the strong reference once with disjoint causal accumulators."""

    if not isinstance(windows, list):
        raise ValueError("windows must be a list")
    if any(not isinstance(window, PublicationWindow) for window in windows):
        raise ValueError("windows must contain PublicationWindow values")
    if not isinstance(initial, dict):
        raise ValueError("initial must be a coordinate-to-value dict")
    if not isinstance(config, SimulationConfig):
        raise ValueError("config must be a SimulationConfig")
    if (
        not _is_strict_int(warmup_end)
        or not _is_strict_int(tuning_end)
        or not 0 <= warmup_end < tuning_end < len(windows)
    ):
        raise ValueError("causal boundaries must satisfy 0 <= warmup < tuning < windows")

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
    tuning = _CausalAccumulator.for_strategy(STRONG_REFERENCE_STRATEGY)
    held_out = _CausalAccumulator.for_strategy(STRONG_REFERENCE_STRATEGY)
    query_templates: dict[tuple[object, ...], _QueryAccountingTemplate] = {}
    predecessor = _validated_predecessor(state)
    for position, window in enumerate(windows):
        transition = advance_strong_publication(
            state,
            window,
            _predecessor=predecessor,
        )
        accounting = _cached_strong_accounting(transition, query_templates)
        held_out.require(accounting)
        if position < tuning_end:
            tuning.require(accounting)
        if warmup_end <= position < tuning_end:
            tuning.measure(accounting, transition.facts.overflow_rows)
        elif position >= tuning_end:
            held_out.measure(accounting, transition.facts.overflow_rows)
        state = transition.state
        predecessor = _validated_predecessor(state)

    _assert_strong_strategy_invariants(state)
    return tuning.result(), held_out.result()


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
