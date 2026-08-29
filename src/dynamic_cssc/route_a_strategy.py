"""Route A's narrow adapter from evidence windows to strategy transitions.

The evidence trace retains every ordered SET reference.  The persistent strategy
state instead consumes one coordinate-sorted net update per touched coordinate.
Keeping that reduction here prevents the three candidates from interpreting the
same evidence window differently.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, replace
from typing import Literal, TypeAlias, cast

from dynamic_cssc.cssc import output_plan_for, publish_component
from dynamic_cssc.events import NetUpdate, PublicationWindow
from dynamic_cssc.output_plan import analyze_output_plan
from dynamic_cssc.route_a_schedule import (
    RouteAPublicationWindow,
    resolve_route_a_publication_window,
)
from dynamic_cssc.route_a_workloads import RouteAAcceptedGroup
from dynamic_cssc.strategy_state import (
    StrategyKind,
    StrategyState,
    StrongStrategyState,
    StrongTransition,
    Transition,
    TransitionFacts,
    advance_publication,
    advance_strong_publication,
    assert_strategy_invariants,
    decode_strong_state,
    initialize_strategy,
    initialize_strong_strategy,
)
from dynamic_cssc.strong_execution import compile_strong_execution
from dynamic_cssc.strong_packed_coo import STRONG_COMPONENT_ID, cloud_page_shapes

__all__ = (
    "ROUTE_A_STRATEGY_CANDIDATES",
    "RouteAAdaptedWindow",
    "RouteACandidateAdvance",
    "RouteACandidateStateAdvance",
    "RouteACandidateTimedAdvance",
    "RouteACandidateState",
    "adapt_route_a_strategy_window",
    "advance_route_a_candidate",
    "advance_route_a_candidate_state_only",
    "advance_route_a_candidate_timed",
    "initialize_route_a_candidate",
)

RouteACandidateId = Literal[
    "periodic-repack/windows=1",
    "padding-reuse",
    "packed-coo-cloud-segmented-delta/segment-width=128",
]
RouteAState: TypeAlias = StrategyState | StrongStrategyState
RouteATransition: TypeAlias = Transition | StrongTransition

ROUTE_A_STRATEGY_CANDIDATES: tuple[RouteACandidateId, ...] = (
    "periodic-repack/windows=1",
    "padding-reuse",
    "packed-coo-cloud-segmented-delta/segment-width=128",
)

_ROWS = frozenset({256, 1_024})
_COLUMNS = 8_193
_EFFECTIVE_SLOTS = 4_096
_MATRIX_VALUE_BOUND = 7
_SEGMENT_WIDTH = 128


@dataclass(frozen=True, slots=True)
class RouteAAdaptedWindow:
    """One evidence window plus its uniquely derived strategy input."""

    route_a_window: RouteAPublicationWindow
    publication_window: PublicationWindow
    accepted_set_transition_count: int
    net_update_count: int


@dataclass(frozen=True, slots=True)
class RouteACandidateState:
    """One exact Route A candidate identity and its independently owned state."""

    candidate_id: RouteACandidateId
    state: RouteAState
    next_window_ordinal: int
    next_global_query_ordinal: int

    def __post_init__(self) -> None:
        if (
            type(self.next_window_ordinal) is not int
            or self.next_window_ordinal < 0
            or type(self.next_global_query_ordinal) is not int
            or self.next_global_query_ordinal < 0
        ):
            raise ValueError("Route A candidate cursors must be nonnegative strict integers")


@dataclass(frozen=True, slots=True)
class RouteACandidateAdvance:
    """The next candidate state and the underlying auditable transition facts."""

    candidate: RouteACandidateState
    adapted_window: RouteAAdaptedWindow
    transition: RouteATransition


@dataclass(frozen=True, slots=True)
class RouteACandidateStateAdvance:
    """One exact state advance that deliberately omits query-plan assembly.

    The evidence window remains unchanged and the global query cursor still
    advances by its exact query count.  Only the query-side plan attached to the
    returned transition is absent.  This is the narrow terminal-snapshot seam
    used by Route A native cases; it cannot execute or emit an earlier query.
    """

    candidate: RouteACandidateState
    adapted_window: RouteAAdaptedWindow
    transition: RouteATransition
    state_transition_nanoseconds: int

    def __post_init__(self) -> None:
        if (
            type(self.state_transition_nanoseconds) is not int
            or self.state_transition_nanoseconds < 0
            or self.transition.facts.query_count != 0
            or self.transition.output_plan is not None
            or (
                type(self.transition) is StrongTransition
                and self.transition.execution_bundle is not None
            )
        ):
            raise ValueError("Route A state-only advance retained query-side work")


@dataclass(frozen=True, slots=True)
class RouteACandidateTimedAdvance:
    """One advance plus non-overlapping monotonic phase observations."""

    advance: RouteACandidateAdvance
    state_transition_nanoseconds: int
    result_assembly_nanoseconds: int

    def __post_init__(self) -> None:
        if (
            type(self.state_transition_nanoseconds) is not int
            or self.state_transition_nanoseconds < 0
            or type(self.result_assembly_nanoseconds) is not int
            or self.result_assembly_nanoseconds < 0
        ):
            raise ValueError("Route A phase timings must be nonnegative integer nanoseconds")


def adapt_route_a_strategy_window(
    groups: tuple[RouteAAcceptedGroup, ...],
    window: RouteAPublicationWindow,
) -> RouteAAdaptedWindow:
    """Resolve exact SET pointers and derive one sorted net-update window."""

    resolved = resolve_route_a_publication_window(groups, window)
    references = window.ordered_set_transition_references
    first_before: dict[tuple[int, int], int] = {}
    last_after: dict[tuple[int, int], int] = {}
    for transition in resolved.ordered_set_transitions:
        coordinate = (transition.row, transition.column)
        if coordinate in last_after and last_after[coordinate] != transition.before:
            raise AssertionError("validated Route A SET continuity changed during reduction")
        first_before.setdefault(coordinate, transition.before)
        last_after[coordinate] = transition.after

    net_updates = tuple(
        NetUpdate(row, column, first_before[(row, column)], last_after[(row, column)])
        for row, column in sorted(first_before)
        if first_before[(row, column)] != last_after[(row, column)]
    )
    publication_window = PublicationWindow(
        index=window.window_ordinal,
        start_time=float(resolved.start_time),
        end_time=float(window.closed_at),
        updates=net_updates,
        query_count=window.query_count,
        reason=window.close_reason,
    )
    return RouteAAdaptedWindow(
        route_a_window=window,
        publication_window=publication_window,
        accepted_set_transition_count=len(references),
        net_update_count=len(net_updates),
    )


def initialize_route_a_candidate(
    candidate_id: str,
    initial_state: dict[tuple[int, int], int],
    *,
    rows: int,
) -> RouteACandidateState:
    """Initialize one of the three preregistered candidates with no shared state."""

    if candidate_id not in ROUTE_A_STRATEGY_CANDIDATES:
        raise ValueError("Route A candidate identity is not preregistered")
    if type(rows) is not int or rows not in _ROWS:
        raise ValueError("Route A rows must be exactly 256 or 1024")
    if type(initial_state) is not dict:
        raise TypeError("Route A initial state must be an exact dict")
    if candidate_id == "packed-coo-cloud-segmented-delta/segment-width=128":
        state: RouteAState = initialize_strong_strategy(
            dict(initial_state),
            rows=rows,
            cols=_COLUMNS,
            effective_slots=_EFFECTIVE_SLOTS,
            segment_width=_SEGMENT_WIDTH,
            partition_rows=rows,
            matrix_value_bound=_MATRIX_VALUE_BOUND,
            max_row_nnz=_COLUMNS,
            reserved_slack_beta=0.0,
        )
    else:
        strategy = (
            "PeriodicRepack" if candidate_id == "periodic-repack/windows=1" else "PaddingReuse-CSSC"
        )
        state = initialize_strategy(
            cast(StrategyKind, strategy),
            dict(initial_state),
            rows=rows,
            cols=_COLUMNS,
            effective_slots=_EFFECTIVE_SLOTS,
            partition_rows=rows,
            matrix_value_bound=_MATRIX_VALUE_BOUND,
            max_row_nnz=_COLUMNS,
            reserved_slack_beta=0.0,
            periodic_repack_windows=1,
            packed_coo_segment_capacity=_SEGMENT_WIDTH,
        )
    return RouteACandidateState(
        candidate_id=cast(RouteACandidateId, candidate_id),
        state=state,
        next_window_ordinal=0,
        next_global_query_ordinal=0,
    )


def _ordinary_version_only_publication(
    state: StrategyState,
    window: PublicationWindow,
) -> Transition:
    if state.strategy not in {"PeriodicRepack", "PaddingReuse-CSSC"}:
        raise ValueError("Route A ordinary state has the wrong strategy")
    if state.delta is not None or state.delta_logical or state.coo_segments:
        raise ValueError("Route A ordinary state has an inadmissible auxiliary component")
    version_ordinal = state.version_ordinal + 1
    version_id = f"v{version_ordinal:08d}"
    if state.strategy == "PeriodicRepack":
        base = publish_component(
            state.logical,
            rows=state.config.rows,
            cols=state.config.cols,
            effective_slots=state.config.effective_slots,
            partition_rows=state.config.partition_rows,
            version_id=version_id,
            component_prefix="base",
        )
        next_state = replace(
            state,
            version_ordinal=version_ordinal,
            version_id=version_id,
            base=base,
            windows_since_repack=0,
            repack_count=state.repack_count + 1,
        )
        facts = TransitionFacts(
            updates=0,
            query_count=window.query_count,
            ci_full_sync_entries=sum(len(chunk.column_indices) for chunk in base.chunks),
            rebuilt_ciphertexts=len(base.chunks),
            rebuilt_output_block_ids=tuple(block.output_block_id for block in base.blocks),
            active_component_ids=(base.component_id,),
        )
    else:
        base = replace(state.base, version_id=version_id)
        next_state = replace(
            state,
            version_ordinal=version_ordinal,
            version_id=version_id,
            base=base,
        )
        facts = TransitionFacts(
            updates=0,
            query_count=window.query_count,
            active_component_ids=(base.component_id,),
        )
    assert_strategy_invariants(next_state)
    output_plan = output_plan_for((base,)) if window.query_count > 0 else None
    if output_plan is not None:
        analyze_output_plan(output_plan)
    return Transition(next_state, facts, output_plan)


def _strong_version_only_publication(
    state: StrongStrategyState,
    window: PublicationWindow,
) -> StrongTransition:
    version_ordinal = state.version_ordinal + 1
    version_id = f"v{version_ordinal:08d}"
    base = replace(state.base, version_id=version_id)
    delta = replace(state.delta, version_id=version_id)
    next_state = replace(
        state,
        version_ordinal=version_ordinal,
        version_id=version_id,
        base=base,
        delta=delta,
    )
    decode_strong_state(next_state)
    bundle = compile_strong_execution(base, delta) if window.query_count > 0 else None
    component_ids = [base.component_id]
    if delta.segments:
        component_ids.append(STRONG_COMPONENT_ID)
    return StrongTransition(
        state=next_state,
        facts=TransitionFacts(
            updates=0,
            query_count=window.query_count,
            delta_ciphertexts=len(cloud_page_shapes(delta)),
            active_component_ids=tuple(component_ids),
        ),
        output_plan=bundle.output_plan if bundle is not None else None,
        execution_bundle=bundle,
    )


def _assemble_route_a_query_result(
    transition: RouteATransition,
    query_count: int,
) -> RouteATransition:
    if query_count == 0:
        return transition
    facts = replace(transition.facts, query_count=query_count)
    state = transition.state
    if type(transition) is StrongTransition:
        if type(state) is not StrongStrategyState:  # pragma: no cover - closed union
            raise AssertionError("Route A strong transition changed state type")
        bundle = compile_strong_execution(state.base, state.delta)
        return StrongTransition(
            state=state,
            facts=facts,
            output_plan=bundle.output_plan,
            execution_bundle=bundle,
        )
    if type(transition) is Transition:
        if type(state) is not StrategyState:  # pragma: no cover - closed union
            raise AssertionError("Route A ordinary transition changed state type")
        components = (state.base,) if state.delta is None else (state.base, state.delta)
        output_plan = output_plan_for(components)
        analyze_output_plan(output_plan)
        return Transition(state=state, facts=facts, output_plan=output_plan)
    raise TypeError("Route A transition has the wrong exact type")


def _advance_route_a_candidate_state(
    candidate: RouteACandidateState,
    groups: tuple[RouteAAcceptedGroup, ...],
    route_a_window: RouteAPublicationWindow,
) -> RouteACandidateStateAdvance:
    """Advance state and exact cursors without constructing a query-side plan."""

    if type(candidate) is not RouteACandidateState:
        raise TypeError("candidate must be an exact RouteACandidateState")
    if type(groups) is not tuple:
        raise TypeError("accepted groups must be an exact tuple")
    adapted_window = adapt_route_a_strategy_window(groups, route_a_window)
    state = candidate.state
    window = adapted_window.route_a_window
    publication_window = adapted_window.publication_window
    if window.window_ordinal != candidate.next_window_ordinal:
        raise ValueError("Route A window ordinal does not match the candidate cursor")
    if (
        window.query_count > 0
        and window.first_global_query_ordinal_or_null != candidate.next_global_query_ordinal
    ):
        raise ValueError("Route A first query ordinal does not match the candidate cursor")
    if state.version_ordinal != window.version_before:
        raise ValueError("Route A candidate version does not match the evidence window")
    update_bearing = adapted_window.accepted_set_transition_count > 0
    if update_bearing != bool(window.ordered_set_transition_references):
        raise ValueError("Route A source transition count is inconsistent")

    state_only_window = replace(publication_window, query_count=0)
    transition_started = time.perf_counter_ns()
    if type(state) is StrongStrategyState:
        if candidate.candidate_id != "packed-coo-cloud-segmented-delta/segment-width=128":
            raise ValueError("Route A strong state has the wrong candidate identity")
        transition: RouteATransition
        transition = (
            advance_strong_publication(state, state_only_window)
            if state_only_window.updates or not update_bearing
            else _strong_version_only_publication(state, state_only_window)
        )
    elif type(state) is StrategyState:
        expected_strategy = {
            "periodic-repack/windows=1": "PeriodicRepack",
            "padding-reuse": "PaddingReuse-CSSC",
        }.get(candidate.candidate_id)
        if state.strategy != expected_strategy:
            raise ValueError("Route A ordinary state has the wrong candidate identity")
        transition = (
            advance_publication(state, state_only_window)
            if state_only_window.updates or not update_bearing
            else _ordinary_version_only_publication(state, state_only_window)
        )
    else:  # pragma: no cover - the exact candidate wrapper owns this type
        raise TypeError("Route A candidate contains the wrong state type")
    transition_finished = time.perf_counter_ns()

    if transition.state.version_ordinal != window.version_after:
        raise AssertionError("Route A strategy transition violated the frozen version rule")
    next_candidate = RouteACandidateState(
        candidate_id=candidate.candidate_id,
        state=transition.state,
        next_window_ordinal=candidate.next_window_ordinal + 1,
        next_global_query_ordinal=(candidate.next_global_query_ordinal + window.query_count),
    )
    return RouteACandidateStateAdvance(
        candidate=next_candidate,
        adapted_window=adapted_window,
        transition=transition,
        state_transition_nanoseconds=transition_finished - transition_started,
    )


def advance_route_a_candidate_state_only(
    candidate: RouteACandidateState,
    groups: tuple[RouteAAcceptedGroup, ...],
    route_a_window: RouteAPublicationWindow,
) -> RouteACandidateStateAdvance:
    """Advance one exact window while intentionally omitting query-plan assembly."""

    return _advance_route_a_candidate_state(candidate, groups, route_a_window)


def advance_route_a_candidate_timed(
    candidate: RouteACandidateState,
    groups: tuple[RouteAAcceptedGroup, ...],
    route_a_window: RouteAPublicationWindow,
) -> RouteACandidateTimedAdvance:
    """Advance one window while separating state work from query-plan assembly."""

    state_advance = _advance_route_a_candidate_state(
        candidate,
        groups,
        route_a_window,
    )
    assembly_started = time.perf_counter_ns()
    transition = _assemble_route_a_query_result(
        state_advance.transition,
        state_advance.adapted_window.route_a_window.query_count,
    )
    assembly_finished = time.perf_counter_ns()
    return RouteACandidateTimedAdvance(
        advance=RouteACandidateAdvance(
            state_advance.candidate,
            state_advance.adapted_window,
            transition,
        ),
        state_transition_nanoseconds=state_advance.state_transition_nanoseconds,
        result_assembly_nanoseconds=assembly_finished - assembly_started,
    )


def advance_route_a_candidate(
    candidate: RouteACandidateState,
    groups: tuple[RouteAAcceptedGroup, ...],
    route_a_window: RouteAPublicationWindow,
) -> RouteACandidateAdvance:
    """Compatibility entry point retaining the exact unphased return type."""

    return advance_route_a_candidate_timed(candidate, groups, route_a_window).advance
