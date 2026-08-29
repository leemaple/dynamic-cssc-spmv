from __future__ import annotations

import json
from fractions import Fraction

import pytest

from dynamic_cssc.route_a_schedule import (
    compile_route_a_window_trace,
    resolve_route_a_publication_window,
)
from dynamic_cssc.route_a_workloads import RouteAAcceptedGroup, RouteASetTransition


def _group(
    accepted_ordinal: int,
    *transitions: RouteASetTransition,
    denominator: int = 100,
) -> RouteAAcceptedGroup:
    return RouteAAcceptedGroup(
        accepted_ordinal=accepted_ordinal,
        logical_time_numerator=accepted_ordinal,
        logical_time_denominator=denominator,
        transitions=transitions,
    )


def _insert(row: int, column: int, after: int = 1) -> RouteASetTransition:
    return RouteASetTransition(
        row=row,
        column=column,
        before=0,
        after=after,
        cause="insert",
    )


def _compile(
    groups: tuple[RouteAAcceptedGroup, ...],
    *,
    rho: Fraction,
):
    return compile_route_a_window_trace(
        groups,
        source_event_trace_sha256="a" * 64,
        shard_identity_sha256="b" * 64,
        rho=rho,
        freshness=Fraction(1),
    )


def test_query_closes_prior_and_current_sets_in_one_window() -> None:
    trace = _compile(
        (_group(0, _insert(0, 10)),)
        + tuple(_group(ordinal) for ordinal in range(1, 9))
        + (_group(9, _insert(0, 11)),),
        rho=Fraction(1, 10),
    )

    assert len(trace.ordered_windows) == 1
    window = trace.ordered_windows[0]
    assert window.close_reason == "query"
    assert window.version_before == 0
    assert window.version_after == 1
    assert window.first_event_group_ordinal_or_null == 0
    assert window.last_event_group_ordinal_or_null == 9
    assert tuple(
        (reference.accepted_group_ordinal, reference.transition_ordinal_within_group)
        for reference in window.ordered_set_transition_references
    ) == ((0, 0), (9, 0))
    assert window.first_global_query_ordinal_or_null == 0
    assert window.query_count == 1


def test_query_only_window_does_not_mint_an_unchanged_publication_version() -> None:
    trace = _compile((_group(0),), rho=Fraction(1))

    assert len(trace.ordered_windows) == 1
    window = trace.ordered_windows[0]
    assert window.close_reason == "query"
    assert window.version_before == 0
    assert window.version_after == 0
    assert window.ordered_set_transition_references == ()
    assert window.first_event_group_ordinal_or_null == 0
    assert window.last_event_group_ordinal_or_null == 0
    assert window.first_global_query_ordinal_or_null == 0
    assert window.query_count == 1
    assert trace.sha256 == (
        "725365fa25e17120827d377a4c373cd0c58fdaf50228ef1a86508655ac501923"
    )
    document = json.loads(trace.document_bytes)
    assert set(document["ordered_windows"][0]) == {
        "close_reason",
        "first_event_group_ordinal_or_null",
        "first_global_query_ordinal_or_null",
        "last_event_group_ordinal_or_null",
        "ordered_set_transition_references",
        "query_count",
        "version_after",
        "version_before",
        "window_ordinal",
    }


def test_mixed_window_excludes_leading_noops_but_includes_trailing_noops() -> None:
    trace = _compile(
        tuple(_group(ordinal) for ordinal in range(3))
        + (_group(3, _insert(0, 10)),)
        + tuple(_group(ordinal) for ordinal in range(4, 10)),
        rho=Fraction(1, 10),
    )

    assert len(trace.ordered_windows) == 1
    window = trace.ordered_windows[0]
    assert window.first_event_group_ordinal_or_null == 3
    assert window.last_event_group_ordinal_or_null == 9
    assert tuple(
        (reference.accepted_group_ordinal, reference.transition_ordinal_within_group)
        for reference in window.ordered_set_transition_references
    ) == ((3, 0),)


def test_finite_trace_flushes_every_remaining_set_once_at_final_group_time() -> None:
    trace = _compile(
        (
            _group(0, _insert(0, 10)),
            _group(1, _insert(0, 11)),
        ),
        rho=Fraction(1, 100),
    )

    assert len(trace.ordered_windows) == 1
    window = trace.ordered_windows[0]
    assert window.close_reason == "finite-trace-end"
    assert window.closed_at == Fraction(1, 100)
    assert window.version_before == 0
    assert window.version_after == 1
    assert tuple(
        (reference.accepted_group_ordinal, reference.transition_ordinal_within_group)
        for reference in window.ordered_set_transition_references
    ) == ((0, 0), (1, 0))
    assert window.first_event_group_ordinal_or_null == 0
    assert window.last_event_group_ordinal_or_null == 1
    assert window.first_global_query_ordinal_or_null is None
    assert window.query_count == 0


def test_pre_group_microbatch_keeps_two_set_group_atomic_at_sixty_five() -> None:
    groups = tuple(
        _group(ordinal, _insert(ordinal, 10)) for ordinal in range(63)
    ) + (
        _group(63, _insert(63, 10), _insert(63, 11)),
        _group(64, _insert(64, 10)),
    )

    trace = _compile(groups, rho=Fraction(1, 100))

    assert [window.close_reason for window in trace.ordered_windows] == [
        "pre-group-microbatch",
        "finite-trace-end",
    ]
    first, second = trace.ordered_windows
    assert len(first.ordered_set_transition_references) == 65
    assert first.last_event_group_ordinal_or_null == 63
    assert first.closed_at == Fraction(64, 100)
    assert first.version_before == 0
    assert first.version_after == 1
    assert tuple(
        (reference.accepted_group_ordinal, reference.transition_ordinal_within_group)
        for reference in first.ordered_set_transition_references[-2:]
    ) == ((63, 0), (63, 1))
    assert len(second.ordered_set_transition_references) == 1
    assert second.first_event_group_ordinal_or_null == 64
    assert second.version_before == 1
    assert second.version_after == 2


def test_freshness_closes_before_group_and_includes_prior_noop_in_range() -> None:
    trace = _compile(
        (
            _group(0, _insert(0, 10), denominator=10),
            _group(1, denominator=10),
            _group(2, denominator=1),
        ),
        rho=Fraction(1, 100),
    )

    assert len(trace.ordered_windows) == 1
    window = trace.ordered_windows[0]
    assert window.close_reason == "one-second-deadline"
    assert window.closed_at == Fraction(1)
    assert window.first_event_group_ordinal_or_null == 0
    assert window.last_event_group_ordinal_or_null == 1


def test_rho_ten_batches_queries_without_expanding_query_records() -> None:
    trace = _compile(
        (
            _group(0, _insert(0, 10)),
            _group(1),
        ),
        rho=Fraction(10),
    )

    first, second = trace.ordered_windows
    assert (first.query_count, first.first_global_query_ordinal_or_null) == (10, 0)
    assert (first.version_before, first.version_after) == (0, 1)
    assert (second.query_count, second.first_global_query_ordinal_or_null) == (10, 10)
    assert (second.version_before, second.version_after) == (1, 1)


def test_rejects_a_set_trace_that_breaks_coordinate_continuity() -> None:
    with pytest.raises(ValueError, match="trace continuity"):
        _compile(
            (
                _group(0, _insert(0, 10, after=1)),
                _group(1, _insert(0, 10, after=2)),
            ),
            rho=Fraction(1, 100),
        )


@pytest.mark.parametrize(
    "rho",
    (Fraction(1, 100), Fraction(1, 10), Fraction(1), Fraction(10)),
)
def test_every_compiled_window_round_trips_through_the_exact_resolver(
    rho: Fraction,
) -> None:
    groups = (
        _group(0, _insert(0, 10)),
        _group(
            1,
            RouteASetTransition(0, 10, 1, 2, "modify"),
        ),
        _group(
            2,
            RouteASetTransition(0, 10, 2, 1, "modify"),
        ),
        _group(
            3,
            RouteASetTransition(0, 10, 1, 0, "delete"),
        ),
        *(_group(ordinal) for ordinal in range(4, 20)),
    )

    trace = _compile(groups, rho=rho)

    for window in trace.ordered_windows:
        resolved = resolve_route_a_publication_window(groups, window)
        assert len(resolved.ordered_set_transitions) == len(
            window.ordered_set_transition_references
        )
