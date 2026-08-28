"""Canonical Route A Publication Window compilation.

The compiler consumes one already accepted semantic trace and produces the
strategy-independent window document frozen by the Route A preregistration.
It never expands a query batch and never performs a strategy transition.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from fractions import Fraction
from typing import Literal

from dynamic_cssc.route_a_contract import route_a_query_batch_counts
from dynamic_cssc.route_a_workloads import RouteAAcceptedGroup, RouteASetTransition

__all__ = (
    "RouteAPublicationWindow",
    "RouteAResolvedWindow",
    "RouteASetTransitionReference",
    "RouteAWindowTrace",
    "compile_route_a_window_trace",
    "resolve_route_a_publication_window",
)

_WINDOW_TRACE_SCHEMA = "dynamic-cssc-route-a-window-trace-v1"
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ROUTE_A_RHOS = frozenset(
    {Fraction(1, 100), Fraction(1, 10), Fraction(1), Fraction(10)}
)
_FRESHNESS = Fraction(1)
_ROWS = 1_024
_COLUMNS = 8_193
_COEFFICIENT_ABS_BOUND = 7

RouteACloseReason = Literal[
    "one-second-deadline",
    "pre-group-microbatch",
    "query",
    "finite-trace-end",
]


def _canonical_json_bytes(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ValueError("Route A window trace is not canonical JSON") from error
    return (rendered + "\n").encode("ascii")


@dataclass(frozen=True, slots=True)
class RouteASetTransitionReference:
    """A pure pointer into one bound semantic-event trace."""

    accepted_group_ordinal: int
    transition_ordinal_within_group: int

    def __post_init__(self) -> None:
        if (
            type(self.accepted_group_ordinal) is not int
            or self.accepted_group_ordinal < 0
            or type(self.transition_ordinal_within_group) is not int
            or self.transition_ordinal_within_group < 0
        ):
            raise ValueError("Route A SET reference ordinals must be nonnegative integers")

    def to_document(self) -> dict[str, int]:
        return {
            "accepted_group_ordinal": self.accepted_group_ordinal,
            "transition_ordinal_within_group": self.transition_ordinal_within_group,
        }


@dataclass(frozen=True, slots=True)
class RouteAPublicationWindow:
    """One typed window plus its nonserialized exact close time."""

    window_ordinal: int
    version_before: int
    version_after: int
    close_reason: RouteACloseReason
    first_event_group_ordinal_or_null: int | None
    last_event_group_ordinal_or_null: int | None
    ordered_set_transition_references: tuple[RouteASetTransitionReference, ...]
    first_global_query_ordinal_or_null: int | None
    query_count: int
    closed_at: Fraction

    def to_document(self) -> dict[str, object]:
        return {
            "close_reason": self.close_reason,
            "first_event_group_ordinal_or_null": self.first_event_group_ordinal_or_null,
            "first_global_query_ordinal_or_null": self.first_global_query_ordinal_or_null,
            "last_event_group_ordinal_or_null": self.last_event_group_ordinal_or_null,
            "ordered_set_transition_references": [
                reference.to_document()
                for reference in self.ordered_set_transition_references
            ],
            "query_count": self.query_count,
            "version_after": self.version_after,
            "version_before": self.version_before,
            "window_ordinal": self.window_ordinal,
        }


@dataclass(frozen=True, slots=True)
class RouteAWindowTrace:
    """The exact canonical bytes shared by all strategies for one shard/rho."""

    ordered_windows: tuple[RouteAPublicationWindow, ...]
    document_bytes: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class RouteAResolvedWindow:
    """One exact window binding resolved against its accepted source trace."""

    start_time: Fraction
    ordered_set_transitions: tuple[RouteASetTransition, ...]


def _validate_transition(transition: RouteASetTransition) -> None:
    if type(transition) is not RouteASetTransition:
        raise TypeError("Route A accepted groups require exact SET transition values")
    if (
        type(transition.row) is not int
        or not 0 <= transition.row < _ROWS
        or type(transition.column) is not int
        or not 0 <= transition.column < _COLUMNS
        or type(transition.before) is not int
        or type(transition.after) is not int
        or not -_COEFFICIENT_ABS_BOUND <= transition.before <= _COEFFICIENT_ABS_BOUND
        or not -_COEFFICIENT_ABS_BOUND <= transition.after <= _COEFFICIENT_ABS_BOUND
        or transition.before == transition.after
        or transition.cause not in {"insert", "modify", "delete"}
    ):
        raise ValueError("Route A SET transition is outside the frozen logical domain")
    if (
        (transition.cause == "insert" and (transition.before != 0 or transition.after == 0))
        or (
            transition.cause == "modify"
            and (transition.before == 0 or transition.after == 0)
        )
        or (transition.cause == "delete" and (transition.before == 0 or transition.after != 0))
    ):
        raise ValueError("Route A SET transition cause does not match its values")


def _validate_group(
    group: RouteAAcceptedGroup,
    expected_ordinal: int,
    previous_time: Fraction | None,
) -> tuple[Fraction, tuple[RouteASetTransition, ...]]:
    if type(group) is not RouteAAcceptedGroup:
        raise TypeError("Route A schedule requires exact accepted-group values")
    if (
        type(group.accepted_ordinal) is not int
        or group.accepted_ordinal != expected_ordinal
        or type(group.logical_time_numerator) is not int
        or group.logical_time_numerator < 0
        or type(group.logical_time_denominator) is not int
        or group.logical_time_denominator <= 0
        or type(group.transitions) is not tuple
        or len(group.transitions) not in {0, 1, 2}
    ):
        raise ValueError("Route A accepted group is outside the frozen schedule domain")
    logical_time = Fraction(
        group.logical_time_numerator,
        group.logical_time_denominator,
    )
    if previous_time is not None and logical_time <= previous_time:
        raise ValueError("Route A accepted-group times must increase strictly")
    for transition in group.transitions:
        _validate_transition(transition)
    return logical_time, group.transitions


def _validated_trace(
    groups: tuple[RouteAAcceptedGroup, ...],
) -> tuple[tuple[Fraction, ...], tuple[tuple[RouteASetTransition, ...], ...]]:
    if type(groups) is not tuple or not groups:
        raise ValueError("Route A schedule requires one nonempty accepted-group tuple")
    times: list[Fraction] = []
    transitions_by_group: list[tuple[RouteASetTransition, ...]] = []
    observed_after: dict[tuple[int, int], int] = {}
    previous_time: Fraction | None = None
    for expected_ordinal, group in enumerate(groups):
        logical_time, transitions = _validate_group(
            group,
            expected_ordinal,
            previous_time,
        )
        for transition in transitions:
            coordinate = (transition.row, transition.column)
            if (
                coordinate in observed_after
                and observed_after[coordinate] != transition.before
            ):
                raise ValueError("Route A SET before value breaks trace continuity")
            observed_after[coordinate] = transition.after
        times.append(logical_time)
        transitions_by_group.append(transitions)
        previous_time = logical_time
    return tuple(times), tuple(transitions_by_group)


def _microbatch_closes_before_group(set_count: int, group_set_count: int) -> bool:
    if group_set_count == 0:
        return False
    if group_set_count == 1:
        return set_count + 1 > 64
    if group_set_count == 2:
        return set_count + 2 > 65
    raise AssertionError("accepted-group validation owns the closed g domain")


def resolve_route_a_publication_window(
    groups: tuple[RouteAAcceptedGroup, ...],
    window: RouteAPublicationWindow,
) -> RouteAResolvedWindow:
    """Validate and resolve one exported window against its exact source trace."""

    times, transitions_by_group = _validated_trace(groups)
    if type(window) is not RouteAPublicationWindow:
        raise TypeError("window must be an exact RouteAPublicationWindow")
    first_group = window.first_event_group_ordinal_or_null
    last_group = window.last_event_group_ordinal_or_null
    if (
        type(window.version_before) is not int
        or window.version_before < 0
        or type(window.version_after) is not int
        or window.version_after < 0
    ):
        raise ValueError("Route A version ordinals must be nonnegative strict integers")
    if (
        type(window.window_ordinal) is not int
        or window.window_ordinal < 0
        or type(first_group) is not int
        or type(last_group) is not int
        or not 0 <= first_group <= last_group < len(groups)
        or type(window.query_count) is not int
        or window.query_count < 0
        or type(window.closed_at) is not Fraction
        or window.close_reason
        not in {
            "one-second-deadline",
            "pre-group-microbatch",
            "query",
            "finite-trace-end",
        }
    ):
        raise ValueError("Route A strategy window has malformed exact fields")

    first_query_ordinal = window.first_global_query_ordinal_or_null
    if window.query_count:
        if type(first_query_ordinal) is not int or first_query_ordinal < 0:
            raise ValueError("Route A query ordinal must be one nonnegative strict integer")
    else:
        if first_query_ordinal is not None:
            raise ValueError("Route A nonquery window must not carry a query ordinal")

    references = window.ordered_set_transition_references
    if type(references) is not tuple:
        raise ValueError("Route A SET references must be a tuple")
    reference_keys: list[tuple[int, int]] = []
    for reference in references:
        if type(reference) is not RouteASetTransitionReference:
            raise TypeError(
                "Route A SET pointers require exact RouteASetTransitionReference values"
            )
        group_ordinal = reference.accepted_group_ordinal
        transition_ordinal = reference.transition_ordinal_within_group
        if (
            type(group_ordinal) is not int
            or group_ordinal < 0
            or type(transition_ordinal) is not int
            or transition_ordinal < 0
        ):
            raise ValueError("Route A SET reference ordinals must be nonnegative integers")
        key = (group_ordinal, transition_ordinal)
        if reference_keys and key <= reference_keys[-1]:
            raise ValueError("Route A SET references must be strictly ordered")
        if not first_group <= group_ordinal <= last_group:
            raise ValueError("Route A SET reference escapes its inclusive group range")
        reference_keys.append(key)

    expected_keys = tuple(
        (group_ordinal, transition_ordinal)
        for group_ordinal in range(first_group, last_group + 1)
        for transition_ordinal in range(len(transitions_by_group[group_ordinal]))
    )
    if references and first_group != references[0].accepted_group_ordinal:
        raise ValueError(
            "Route A update range must start at its earliest referenced SET group"
        )
    if tuple(reference_keys) != expected_keys:
        raise ValueError(
            "Route A window references must identify all and only SETs in its inclusive range"
        )

    resolved = tuple(
        transitions_by_group[group_ordinal][transition_ordinal]
        for group_ordinal, transition_ordinal in reference_keys
    )
    if references:
        if window.version_after != window.version_before + 1:
            raise ValueError("Route A SET-bearing window must advance exactly one version")
        if window.query_count > 0 and window.close_reason != "query":
            raise ValueError("Route A query-bearing window must use the query close reason")
        if window.query_count == 0 and window.close_reason == "query":
            raise ValueError("Route A nonquery window cannot use the query close reason")
        start_time = times[first_group]
    else:
        if window.version_after != window.version_before:
            raise ValueError("Route A query-only window must retain its version")
        if (
            window.close_reason != "query"
            or window.query_count <= 0
            or first_group != last_group
        ):
            raise ValueError(
                "Route A query-only window must use the query reason on one group"
            )
        start_time = times[first_group]

    if references:
        running_set_count = len(transitions_by_group[first_group])
        deadline = start_time + _FRESHNESS
        for group_ordinal in range(first_group + 1, last_group + 1):
            if times[group_ordinal] >= deadline:
                raise ValueError("Route A update window crossed its freshness deadline")
            group_set_count = len(transitions_by_group[group_ordinal])
            if _microbatch_closes_before_group(running_set_count, group_set_count):
                raise ValueError("Route A update window crossed a microbatch boundary")
            running_set_count += group_set_count

    if window.close_reason in {"query", "finite-trace-end"}:
        expected_close_time = times[last_group]
        if window.close_reason == "finite-trace-end" and last_group != len(groups) - 1:
            raise ValueError("Route A finite-trace window must end at the final group")
    elif window.close_reason == "pre-group-microbatch":
        next_group = last_group + 1
        if next_group >= len(groups):
            raise ValueError("Route A pre-group close requires one following group")
        if times[next_group] >= start_time + _FRESHNESS:
            raise ValueError("Route A freshness deadline must precede the microbatch close")
        if not _microbatch_closes_before_group(
            len(references), len(transitions_by_group[next_group])
        ):
            raise ValueError("Route A pre-group close lacks its exact microbatch trigger")
        expected_close_time = times[next_group]
    elif window.close_reason == "one-second-deadline":
        next_group = last_group + 1
        if next_group >= len(groups):
            raise ValueError("Route A deadline close requires one following group")
        expected_close_time = start_time + _FRESHNESS
        if times[next_group] < expected_close_time:
            raise ValueError("Route A deadline close precedes its first eligible group")
    else:  # pragma: no cover - the exact field check owns this domain
        raise AssertionError("Route A close reason validation is incomplete")
    if window.closed_at != expected_close_time:
        raise ValueError("Route A window close time does not match its exact reason")

    return RouteAResolvedWindow(
        start_time=start_time,
        ordered_set_transitions=resolved,
    )


def compile_route_a_window_trace(
    groups: tuple[RouteAAcceptedGroup, ...],
    *,
    source_event_trace_sha256: str,
    shard_identity_sha256: str,
    rho: Fraction,
    freshness: Fraction,
) -> RouteAWindowTrace:
    """Compile one exact Route A window trace without strategy-side work."""

    times, transitions_by_group = _validated_trace(groups)
    if (
        type(source_event_trace_sha256) is not str
        or _LOWER_SHA256.fullmatch(source_event_trace_sha256) is None
        or type(shard_identity_sha256) is not str
        or _LOWER_SHA256.fullmatch(shard_identity_sha256) is None
    ):
        raise ValueError("Route A schedule identity requires lowercase SHA-256 values")
    if type(rho) is not Fraction or rho not in _ROUTE_A_RHOS:
        raise ValueError("rho must be one exact preregistered Route A ratio")
    if type(freshness) is not Fraction or freshness != _FRESHNESS:
        raise ValueError("freshness must be the exact preregistered one second")

    query_counts = route_a_query_batch_counts(len(groups), rho)
    windows: list[RouteAPublicationWindow] = []
    pending_references: list[RouteASetTransitionReference] = []
    pending_start_time: Fraction | None = None
    version = 0
    next_query_ordinal = 0

    def close_window(
        *,
        close_reason: RouteACloseReason,
        last_group_ordinal: int,
        closed_at: Fraction,
        query_count: int,
    ) -> None:
        nonlocal pending_start_time, version, next_query_ordinal
        has_updates = bool(pending_references)
        if not has_updates and (close_reason != "query" or query_count <= 0):
            raise AssertionError("Route A never emits an empty non-query window")
        if has_updates:
            first_group_ordinal = pending_references[0].accepted_group_ordinal
            version_after = version + 1
        else:
            first_group_ordinal = last_group_ordinal
            version_after = version
        if first_group_ordinal > last_group_ordinal:
            raise AssertionError("Route A window range is not inclusive and ordered")
        first_query = next_query_ordinal if query_count else None
        windows.append(
            RouteAPublicationWindow(
                window_ordinal=len(windows),
                version_before=version,
                version_after=version_after,
                close_reason=close_reason,
                first_event_group_ordinal_or_null=first_group_ordinal,
                last_event_group_ordinal_or_null=last_group_ordinal,
                ordered_set_transition_references=tuple(pending_references),
                first_global_query_ordinal_or_null=first_query,
                query_count=query_count,
                closed_at=closed_at,
            )
        )
        version = version_after
        next_query_ordinal += query_count
        pending_references.clear()
        pending_start_time = None

    for expected_ordinal, logical_time in enumerate(times):
        transitions = transitions_by_group[expected_ordinal]

        if (
            pending_start_time is not None
            and logical_time >= pending_start_time + freshness
        ):
            close_window(
                close_reason="one-second-deadline",
                last_group_ordinal=expected_ordinal - 1,
                closed_at=pending_start_time + freshness,
                query_count=0,
            )
        if pending_references and _microbatch_closes_before_group(
            len(pending_references), len(transitions)
        ):
            close_window(
                close_reason="pre-group-microbatch",
                last_group_ordinal=expected_ordinal - 1,
                closed_at=logical_time,
                query_count=0,
            )

        for transition_ordinal, _transition in enumerate(transitions):
            if pending_start_time is None:
                pending_start_time = logical_time
            pending_references.append(
                RouteASetTransitionReference(
                    accepted_group_ordinal=expected_ordinal,
                    transition_ordinal_within_group=transition_ordinal,
                )
            )

        query_count = query_counts[expected_ordinal]
        if query_count:
            close_window(
                close_reason="query",
                last_group_ordinal=expected_ordinal,
                closed_at=logical_time,
                query_count=query_count,
            )
    if pending_references:
        close_window(
            close_reason="finite-trace-end",
            last_group_ordinal=len(groups) - 1,
            closed_at=times[-1],
            query_count=0,
        )

    document_bytes = _canonical_json_bytes(
        {
            "freshness_denominator": freshness.denominator,
            "freshness_numerator": freshness.numerator,
            "ordered_windows": [window.to_document() for window in windows],
            "rho_denominator": rho.denominator,
            "rho_numerator": rho.numerator,
            "schema_version": _WINDOW_TRACE_SCHEMA,
            "shard_identity_sha256": shard_identity_sha256,
            "source_event_trace_sha256": source_event_trace_sha256,
        }
    )
    return RouteAWindowTrace(
        ordered_windows=tuple(windows),
        document_bytes=document_bytes,
        sha256=hashlib.sha256(document_bytes).hexdigest(),
    )
