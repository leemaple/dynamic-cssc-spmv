from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from fractions import Fraction

import pytest

import dynamic_cssc.route_a_strategy as route_a_strategy_module
import dynamic_cssc.strategy_state as strategy_state_module
from dynamic_cssc.cssc import PublishedComponent
from dynamic_cssc.events import NetUpdate
from dynamic_cssc.output_plan import OutputPlan
from dynamic_cssc.route_a_schedule import (
    RouteAPublicationWindow,
    RouteASetTransitionReference,
)
from dynamic_cssc.route_a_strategy import (
    ROUTE_A_STRATEGY_CANDIDATES,
    adapt_route_a_strategy_window,
    advance_route_a_candidate,
    advance_route_a_candidate_timed,
    initialize_route_a_candidate,
)
from dynamic_cssc.route_a_workloads import RouteAAcceptedGroup, RouteASetTransition
from dynamic_cssc.strong_execution import StrongExecutionBundle
from dynamic_cssc.strong_packed_coo import SegmentedDeltaState


def _group(
    ordinal: int,
    *transitions: RouteASetTransition,
) -> RouteAAcceptedGroup:
    return RouteAAcceptedGroup(
        accepted_ordinal=ordinal,
        logical_time_numerator=ordinal,
        logical_time_denominator=100,
        transitions=transitions,
    )


def _window(
    *references: RouteASetTransitionReference,
    ordinal: int = 0,
    version_before: int = 0,
    version_after: int = 1,
    query_count: int = 0,
    first_group: int = 0,
    last_group: int = 0,
) -> RouteAPublicationWindow:
    return RouteAPublicationWindow(
        window_ordinal=ordinal,
        version_before=version_before,
        version_after=version_after,
        close_reason="query" if query_count else "finite-trace-end",
        first_event_group_ordinal_or_null=first_group,
        last_event_group_ordinal_or_null=last_group,
        ordered_set_transition_references=references,
        first_global_query_ordinal_or_null=0 if query_count else None,
        query_count=query_count,
        closed_at=Fraction(last_group, 100),
    )


def test_adapter_retains_set_count_but_nets_repeated_coordinates() -> None:
    groups = (
        _group(
            0,
            RouteASetTransition(1, 3, 0, 2, "insert"),
            RouteASetTransition(0, 2, 0, 4, "insert"),
        ),
        _group(
            1,
            RouteASetTransition(1, 3, 2, 5, "modify"),
            RouteASetTransition(0, 2, 4, 0, "delete"),
        ),
    )
    window = _window(
        RouteASetTransitionReference(0, 0),
        RouteASetTransitionReference(0, 1),
        RouteASetTransitionReference(1, 0),
        RouteASetTransitionReference(1, 1),
        last_group=1,
    )

    adapted = adapt_route_a_strategy_window(groups, window)

    assert adapted.accepted_set_transition_count == 4
    assert adapted.net_update_count == 1
    assert adapted.publication_window.updates == (NetUpdate(1, 3, 0, 5),)
    assert adapted.publication_window.query_count == 0


@pytest.mark.parametrize("candidate_id", ROUTE_A_STRATEGY_CANDIDATES)
def test_all_candidates_share_one_adapted_window_and_preserve_query_only_version(
    candidate_id: str,
) -> None:
    update_groups = (_group(0, RouteASetTransition(0, 1, 0, 3, "insert")),)
    update = adapt_route_a_strategy_window(
        update_groups,
        _window(RouteASetTransitionReference(0, 0)),
    )
    query_groups = (_group(0),)
    query_only = adapt_route_a_strategy_window(
        query_groups,
        _window(
            ordinal=1,
            version_before=1,
            version_after=1,
            query_count=2,
        ),
    )
    candidate = initialize_route_a_candidate(
        candidate_id,
        {},
        rows=256,
    )

    updated = advance_route_a_candidate(
        candidate,
        update_groups,
        update.route_a_window,
    )
    queried = advance_route_a_candidate(
        updated.candidate,
        query_groups,
        query_only.route_a_window,
    )

    assert updated.candidate.state.version_ordinal == 1
    assert updated.candidate.state.logical == {(0, 1): 3}
    assert queried.candidate.state.version_ordinal == 1
    assert queried.candidate.state.logical == {(0, 1): 3}
    assert queried.candidate.next_window_ordinal == 2
    assert queried.candidate.next_global_query_ordinal == 2
    assert queried.transition.facts.query_count == 2


@pytest.mark.parametrize("candidate_id", ROUTE_A_STRATEGY_CANDIDATES)
def test_set_bearing_net_zero_window_still_advances_exactly_one_version(
    candidate_id: str,
) -> None:
    groups = (
        _group(
            0,
            RouteASetTransition(0, 1, 3, 4, "modify"),
            RouteASetTransition(0, 1, 4, 3, "modify"),
        ),
    )
    adapted = adapt_route_a_strategy_window(
        groups,
        _window(
            RouteASetTransitionReference(0, 0),
            RouteASetTransitionReference(0, 1),
        ),
    )
    assert adapted.publication_window.updates == ()
    candidate = initialize_route_a_candidate(
        candidate_id,
        {(0, 1): 3},
        rows=256,
    )

    advanced = advance_route_a_candidate(
        candidate,
        groups,
        adapted.route_a_window,
    )

    assert advanced.candidate.state.version_ordinal == 1
    assert advanced.candidate.state.logical == {(0, 1): 3}
    assert advanced.transition.facts.updates == 0


@pytest.mark.parametrize("candidate_id", ROUTE_A_STRATEGY_CANDIDATES)
def test_zero_query_net_zero_window_compiles_no_query_side_plan(
    candidate_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    groups = (
        _group(
            0,
            RouteASetTransition(0, 1, 3, 4, "modify"),
            RouteASetTransition(0, 1, 4, 3, "modify"),
        ),
    )
    adapted = adapt_route_a_strategy_window(
        groups,
        _window(
            RouteASetTransitionReference(0, 0),
            RouteASetTransitionReference(0, 1),
        ),
    )
    candidate = initialize_route_a_candidate(
        candidate_id,
        {(0, 1): 3},
        rows=256,
    )

    def reject_query_plan(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("a zero-query Route A window compiled a query-side plan")

    monkeypatch.setattr(route_a_strategy_module, "output_plan_for", reject_query_plan)
    monkeypatch.setattr(
        route_a_strategy_module,
        "compile_strong_execution",
        reject_query_plan,
    )

    advanced = advance_route_a_candidate(
        candidate,
        groups,
        adapted.route_a_window,
    )

    assert advanced.transition.output_plan is None
    if candidate_id == "packed-coo-cloud-segmented-delta/segment-width=128":
        assert advanced.transition.execution_bundle is None


@pytest.mark.parametrize("candidate_id", ROUTE_A_STRATEGY_CANDIDATES)
def test_query_bearing_net_zero_window_compiles_once_after_version_rebind(
    candidate_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    groups = (
        _group(
            0,
            RouteASetTransition(0, 1, 3, 4, "modify"),
            RouteASetTransition(0, 1, 4, 3, "modify"),
        ),
    )
    adapted = adapt_route_a_strategy_window(
        groups,
        _window(
            RouteASetTransitionReference(0, 0),
            RouteASetTransitionReference(0, 1),
            query_count=1,
        ),
    )
    candidate = initialize_route_a_candidate(
        candidate_id,
        {(0, 1): 3},
        rows=256,
    )
    observed_versions: list[tuple[str, ...]] = []
    real_output_plan_for = route_a_strategy_module.output_plan_for
    real_compile_strong_execution = route_a_strategy_module.compile_strong_execution

    def observed_output_plan_for(
        components: Sequence[PublishedComponent],
    ) -> OutputPlan:
        observed_versions.append(
            tuple(component.version_id for component in components)
        )
        return real_output_plan_for(components)

    def observed_strong_compilation(
        base: PublishedComponent,
        delta: SegmentedDeltaState,
    ) -> StrongExecutionBundle:
        observed_versions.append(
            (base.version_id, delta.version_id)
        )
        return real_compile_strong_execution(base, delta)

    monkeypatch.setattr(
        route_a_strategy_module,
        "output_plan_for",
        observed_output_plan_for,
    )
    monkeypatch.setattr(
        route_a_strategy_module,
        "compile_strong_execution",
        observed_strong_compilation,
    )

    advanced = advance_route_a_candidate(
        candidate,
        groups,
        adapted.route_a_window,
    )

    assert observed_versions == [
        ("v00000001", "v00000001")
        if candidate_id == "packed-coo-cloud-segmented-delta/segment-width=128"
        else ("v00000001",)
    ]
    assert advanced.transition.output_plan is not None


@pytest.mark.parametrize("candidate_id", ROUTE_A_STRATEGY_CANDIDATES)
def test_timed_advance_separates_state_transition_from_result_assembly(
    candidate_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    groups = (_group(0, RouteASetTransition(0, 1, 0, 3, "insert")),)
    window = _window(RouteASetTransitionReference(0, 0), query_count=1)
    candidate = initialize_route_a_candidate(candidate_id, {}, rows=256)
    clock = iter((100, 140, 200, 275))
    monkeypatch.setattr(
        route_a_strategy_module.time,
        "perf_counter_ns",
        lambda: next(clock),
    )

    timed = advance_route_a_candidate_timed(candidate, groups, window)

    assert timed.state_transition_nanoseconds == 40
    assert timed.result_assembly_nanoseconds == 75
    assert timed.advance.transition.facts.query_count == 1
    assert timed.advance.transition.output_plan is not None
    assert timed.advance.candidate.state.logical == {(0, 1): 3}


@pytest.mark.parametrize("candidate_id", ROUTE_A_STRATEGY_CANDIDATES)
def test_timed_and_compatibility_advance_are_semantically_identical(
    candidate_id: str,
) -> None:
    groups = (_group(0, RouteASetTransition(0, 1, 0, 3, "insert")),)
    window = _window(RouteASetTransitionReference(0, 0), query_count=1)
    candidate = initialize_route_a_candidate(candidate_id, {}, rows=256)

    timed = advance_route_a_candidate_timed(candidate, groups, window)
    compatible = advance_route_a_candidate(candidate, groups, window)

    assert timed.advance == compatible


@pytest.mark.parametrize("candidate_id", ROUTE_A_STRATEGY_CANDIDATES)
def test_zero_query_nonzero_update_compiles_no_query_side_plan(
    candidate_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    groups = (_group(0, RouteASetTransition(0, 1, 0, 3, "insert")),)
    adapted = adapt_route_a_strategy_window(
        groups,
        _window(RouteASetTransitionReference(0, 0)),
    )
    candidate = initialize_route_a_candidate(candidate_id, {}, rows=256)

    def reject_query_plan(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("a zero-query update compiled a query-side plan")

    monkeypatch.setattr(strategy_state_module, "output_plan_for", reject_query_plan)
    monkeypatch.setattr(
        strategy_state_module,
        "_compile_strong_bundle",
        reject_query_plan,
    )

    advanced = advance_route_a_candidate(
        candidate,
        groups,
        adapted.route_a_window,
    )

    assert advanced.candidate.state.logical == {(0, 1): 3}
    assert advanced.transition.output_plan is None
    if candidate_id == "packed-coo-cloud-segmented-delta/segment-width=128":
        assert advanced.transition.execution_bundle is None


def test_candidate_cursor_rejects_skipped_duplicate_and_retargeted_query_windows() -> None:
    groups = (
        _group(0),
        _group(1, RouteASetTransition(0, 1, 0, 3, "insert")),
    )
    query_only = _window(
        version_before=0,
        version_after=0,
        query_count=1,
    )
    update = _window(
        RouteASetTransitionReference(1, 0),
        ordinal=1,
        version_before=0,
        version_after=1,
        first_group=1,
        last_group=1,
    )
    candidate = initialize_route_a_candidate(
        "padding-reuse",
        {},
        rows=256,
    )

    with pytest.raises(ValueError, match="window ordinal"):
        advance_route_a_candidate(candidate, groups, update)
    with pytest.raises(ValueError, match="query ordinal"):
        advance_route_a_candidate(
            candidate,
            groups,
            replace(query_only, first_global_query_ordinal_or_null=7),
        )

    queried = advance_route_a_candidate(candidate, groups, query_only)
    with pytest.raises(ValueError, match="window ordinal"):
        advance_route_a_candidate(queried.candidate, groups, query_only)

    updated = advance_route_a_candidate(queried.candidate, groups, update)
    assert updated.candidate.next_window_ordinal == 2
    assert updated.candidate.next_global_query_ordinal == 1


def test_forged_adapted_window_cannot_reach_a_candidate_transition() -> None:
    groups = (_group(0, RouteASetTransition(0, 1, 0, 3, "insert")),)
    window = _window(RouteASetTransitionReference(0, 0))
    adapted = adapt_route_a_strategy_window(groups, window)
    forged = replace(
        adapted,
        publication_window=replace(
            adapted.publication_window,
            updates=(NetUpdate(0, 2, 0, 5),),
        ),
    )
    candidate = initialize_route_a_candidate("padding-reuse", {}, rows=256)

    with pytest.raises(TypeError, match="accepted groups"):
        advance_route_a_candidate(
            candidate,
            forged,  # type: ignore[arg-type]
            window,
        )


def test_adapter_rejects_noncontinuous_same_coordinate_references() -> None:
    groups = (
        _group(0, RouteASetTransition(0, 1, 0, 3, "insert")),
        _group(1, RouteASetTransition(0, 1, 2, 4, "modify")),
    )
    window = _window(
        RouteASetTransitionReference(0, 0),
        RouteASetTransitionReference(1, 0),
        last_group=1,
    )

    with pytest.raises(ValueError, match="continuity"):
        adapt_route_a_strategy_window(groups, window)


def test_adapter_rejects_a_nonexact_set_reference_object() -> None:
    groups = (_group(0, RouteASetTransition(0, 1, 0, 3, "insert")),)
    window = _window(object())  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="exact RouteASetTransitionReference"):
        adapt_route_a_strategy_window(groups, window)


def test_adapter_rejects_a_forged_negative_set_reference_ordinal() -> None:
    groups = (_group(0, RouteASetTransition(0, 1, 0, 3, "insert")),)
    reference = object.__new__(RouteASetTransitionReference)
    object.__setattr__(reference, "accepted_group_ordinal", 0)
    object.__setattr__(reference, "transition_ordinal_within_group", -1)

    with pytest.raises(ValueError, match="nonnegative integers"):
        adapt_route_a_strategy_window(groups, _window(reference))


def test_adapter_rejects_equal_accepted_group_times() -> None:
    groups = (
        _group(0, RouteASetTransition(0, 1, 0, 3, "insert")),
        RouteAAcceptedGroup(
            accepted_ordinal=1,
            logical_time_numerator=0,
            logical_time_denominator=100,
            transitions=(RouteASetTransition(0, 1, 3, 4, "modify"),),
        ),
    )
    window = _window(
        RouteASetTransitionReference(0, 0),
        RouteASetTransitionReference(1, 0),
        last_group=1,
    )

    with pytest.raises(ValueError, match="increase strictly"):
        adapt_route_a_strategy_window(groups, window)


def test_adapter_rejects_missing_set_references_inside_the_window_range() -> None:
    groups = (
        _group(
            0,
            RouteASetTransition(0, 1, 0, 3, "insert"),
            RouteASetTransition(0, 2, 0, 4, "insert"),
        ),
    )
    window = _window(RouteASetTransitionReference(0, 1))

    with pytest.raises(ValueError, match="all and only"):
        adapt_route_a_strategy_window(groups, window)


def test_adapter_rejects_a_leading_noop_group_spliced_into_update_range() -> None:
    groups = (
        _group(0),
        _group(1, RouteASetTransition(0, 1, 0, 3, "insert")),
    )
    window = _window(
        RouteASetTransitionReference(1, 0),
        first_group=0,
        last_group=1,
    )

    with pytest.raises(ValueError, match="earliest referenced SET"):
        adapt_route_a_strategy_window(groups, window)


def test_adapter_rejects_query_only_window_with_a_nonquery_reason() -> None:
    groups = (_group(0),)
    window = replace(
        _window(version_after=0, query_count=1),
        close_reason="finite-trace-end",
    )

    with pytest.raises(ValueError, match="query-only.*reason"):
        adapt_route_a_strategy_window(groups, window)


@pytest.mark.parametrize("forged_ordinal", [-1, True])
def test_adapter_rejects_a_noncanonical_first_query_ordinal(
    forged_ordinal: object,
) -> None:
    groups = (_group(0),)
    window = replace(
        _window(version_after=0, query_count=1),
        first_global_query_ordinal_or_null=forged_ordinal,
    )

    with pytest.raises(ValueError, match="query ordinal"):
        adapt_route_a_strategy_window(groups, window)


@pytest.mark.parametrize(
    ("version_before", "version_after"),
    [(True, 2), (0, True)],
)
def test_adapter_rejects_boolean_versions(
    version_before: object,
    version_after: object,
) -> None:
    groups = (_group(0, RouteASetTransition(0, 1, 0, 3, "insert")),)
    window = _window(
        RouteASetTransitionReference(0, 0),
        version_before=version_before,  # type: ignore[arg-type]
        version_after=version_after,  # type: ignore[arg-type]
    )

    with pytest.raises(ValueError, match="version ordinals"):
        adapt_route_a_strategy_window(groups, window)


def test_adapter_rejects_a_finite_trace_close_at_the_wrong_time() -> None:
    groups = (_group(0, RouteASetTransition(0, 1, 0, 3, "insert")),)
    window = replace(
        _window(RouteASetTransitionReference(0, 0)),
        closed_at=Fraction(1, 100),
    )

    with pytest.raises(ValueError, match="close time"):
        adapt_route_a_strategy_window(groups, window)


def test_adapter_rejects_a_set_cause_that_disagrees_with_its_values() -> None:
    groups = (_group(0, RouteASetTransition(0, 1, 0, 3, "delete")),)
    window = _window(RouteASetTransitionReference(0, 0))

    with pytest.raises(ValueError, match="cause"):
        adapt_route_a_strategy_window(groups, window)
