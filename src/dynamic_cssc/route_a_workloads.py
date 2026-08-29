"""Exact synthetic source construction for the preregistered Route A matrix."""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass
from typing import Literal

__all__ = (
    "RouteAAcceptedGroup",
    "RouteASetTransition",
    "RouteASyntheticTrace",
    "generate_route_a_formal_trace",
    "generate_route_a_qualification_trace",
    "validate_route_a_synthetic_trace",
)

_COLUMNS = 8_193
_INITIAL_NONZEROS_PER_ROW = 8
_COEFFICIENT_ABS_BOUND = 7
_INITIAL_STATE_SCHEMA = "dynamic-cssc-route-a-synthetic-initial-state-v1"
_EVENT_TRACE_SCHEMA = "dynamic-cssc-route-a-synthetic-event-trace-v1"
_SCALES = {
    "S": (256, 512),
    "M": (1_024, 2_048),
}
_QUALIFICATION_SEED = 20_260_821
_FORMAL_SEEDS = frozenset({20_260_822, 20_260_823, 20_260_824})


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
        raise ValueError("Route A workload identity is not canonical JSON") from error
    return (rendered + "\n").encode("ascii")


@dataclass(frozen=True, slots=True)
class RouteASetTransition:
    row: int
    column: int
    before: int
    after: int
    cause: Literal["insert", "modify", "delete"]


@dataclass(frozen=True, slots=True)
class RouteAAcceptedGroup:
    accepted_ordinal: int
    logical_time_numerator: int
    logical_time_denominator: int
    transitions: tuple[RouteASetTransition, ...]


@dataclass(frozen=True, slots=True)
class RouteASyntheticTrace:
    suite_role: Literal["qualification", "formal"]
    scale: Literal["S", "M"]
    formal_seed: int
    rows: int
    columns: int
    initial_nonzeros: tuple[tuple[int, int, int], ...]
    initial_state_bytes: bytes
    initial_state_sha256: str
    accepted_groups: tuple[RouteAAcceptedGroup, ...]
    event_trace_bytes: bytes
    event_trace_sha256: str

    def initial_state(self) -> dict[tuple[int, int], int]:
        """Return a detached logical-state copy for one strategy evaluation."""

        return {(row, column): value for row, column, value in self.initial_nonzeros}


def _new_column(
    rng: random.Random,
    row_state: dict[int, int],
) -> int | None:
    for _ in range(min(2 * _COLUMNS, 2_048)):
        column = rng.randrange(_COLUMNS)
        if column not in row_state:
            return column
    available = [column for column in range(_COLUMNS) if column not in row_state]
    return rng.choice(available) if available else None


def _modified_value(rng: random.Random, current: int) -> int:
    candidates = [
        current + delta
        for delta in (-1, 1, 2)
        if current + delta != 0 and abs(current + delta) <= _COEFFICIENT_ABS_BOUND
    ]
    return rng.choice(candidates) if candidates else current


def _initial_state(
    rows: int,
    seed: int,
) -> tuple[list[dict[int, int]], tuple[tuple[int, int, int], ...]]:
    rng = random.Random(seed)
    row_states = [dict() for _ in range(rows)]
    for row in range(rows):
        for column in rng.sample(range(_COLUMNS), _INITIAL_NONZEROS_PER_ROW):
            row_states[row][column] = rng.randint(1, _COEFFICIENT_ABS_BOUND)
    ordered = tuple(
        (row, column, value)
        for row, row_state in enumerate(row_states)
        for column, value in sorted(row_state.items())
    )
    return row_states, ordered


def generate_route_a_qualification_trace(
    *,
    scale: str,
    qualification_seed: int,
) -> RouteASyntheticTrace:
    """Generate the one permanently non-admissible qualification trace."""

    if (
        scale != "M"
        or type(qualification_seed) is not int
        or qualification_seed != _QUALIFICATION_SEED
    ):
        raise ValueError("qualification trace scope must be exactly M/20260821")
    return _generate_route_a_synthetic_trace(
        suite_role="qualification",
        scale="M",
        formal_seed=qualification_seed,
    )


def generate_route_a_formal_trace(
    *,
    scale: str,
    formal_seed: int,
) -> RouteASyntheticTrace:
    """Generate one exact formal S/M accepted-event trace."""

    if (
        scale not in _SCALES
        or type(formal_seed) is not int
        or formal_seed not in _FORMAL_SEEDS
    ):
        raise ValueError(
            "formal trace scope requires S/M and seed 20260822..20260824"
        )
    return _generate_route_a_synthetic_trace(
        suite_role="formal",
        scale=scale,
        formal_seed=formal_seed,
    )


def validate_route_a_synthetic_trace(
    trace: RouteASyntheticTrace,
) -> RouteASyntheticTrace:
    """Recompute and bind every typed field to the registered source bytes."""

    if type(trace) is not RouteASyntheticTrace:
        raise TypeError("trace must be an exact RouteASyntheticTrace")
    if trace.suite_role == "qualification":
        expected = generate_route_a_qualification_trace(
            scale=trace.scale,
            qualification_seed=trace.formal_seed,
        )
    elif trace.suite_role == "formal":
        expected = generate_route_a_formal_trace(
            scale=trace.scale,
            formal_seed=trace.formal_seed,
        )
    else:  # pragma: no cover - the frozen dataclass type owns this field domain
        raise ValueError("Route A synthetic trace has an unknown suite role")
    if trace != expected:
        raise ValueError("Route A typed trace differs from its canonical source bytes")
    return trace


def _generate_route_a_synthetic_trace(
    *,
    suite_role: Literal["qualification", "formal"],
    scale: str,
    formal_seed: int,
) -> RouteASyntheticTrace:
    """Construct canonical bytes after the public suite-role gate closes."""

    rows, accepted_update_count = _SCALES[scale]
    row_states, initial_nonzeros = _initial_state(rows, formal_seed)
    initial_state_bytes = _canonical_json_bytes(
        {
            "columns": _COLUMNS,
            "ordered_nonzeros": initial_nonzeros,
            "rows": rows,
            "schema_version": _INITIAL_STATE_SCHEMA,
        }
    )
    rng = random.Random(formal_seed + 1)
    groups: list[RouteAAcceptedGroup] = []
    attempted_iterations = 0
    while len(groups) < accepted_update_count:
        attempted_iterations += 1
        if attempted_iterations > accepted_update_count * _COLUMNS:
            raise RuntimeError("Route A synthetic generator exhausted its finite attempt bound")
        row = rng.randrange(rows)
        row_state = row_states[row]
        existing = sorted(row_state)
        selector = rng.random()
        cause: Literal["insert", "modify", "delete"]

        if selector < 0.45:
            column = _new_column(rng, row_state)
            if column is None and existing:
                column = rng.choice(existing)
                before = row_state[column]
                after = _modified_value(rng, before)
                cause = "modify"
            elif column is None:
                continue
            else:
                before = 0
                after = rng.randint(1, _COEFFICIENT_ABS_BOUND)
                cause = "insert"
        elif selector < 0.80 and existing:
            column = rng.choice(existing)
            before = row_state[column]
            after = _modified_value(rng, before)
            cause = "modify"
        elif existing:
            column = rng.choice(existing)
            before = row_state[column]
            after = 0
            cause = "delete"
        else:
            column = _new_column(rng, row_state)
            if column is None:
                continue
            before = 0
            after = rng.randint(1, _COEFFICIENT_ABS_BOUND)
            cause = "insert"

        if after == 0:
            row_state.pop(column, None)
        else:
            row_state[column] = after
        accepted_ordinal = len(groups)
        groups.append(
            RouteAAcceptedGroup(
                accepted_ordinal=accepted_ordinal,
                logical_time_numerator=accepted_ordinal,
                logical_time_denominator=100,
                transitions=(
                    RouteASetTransition(
                        row=row,
                        column=column,
                        before=before,
                        after=after,
                        cause=cause,
                    ),
                ),
            )
        )

    frozen_groups = tuple(groups)
    initial_state_sha256 = hashlib.sha256(initial_state_bytes).hexdigest()
    event_trace_bytes = _canonical_json_bytes(
        {
            "accepted_group_count": len(frozen_groups),
            "columns": _COLUMNS,
            "formal_seed": formal_seed,
            "initial_state_sha256": initial_state_sha256,
            "ordered_groups": [
                {
                    "accepted_group_ordinal": group.accepted_ordinal,
                    "logical_time_denominator": group.logical_time_denominator,
                    "logical_time_numerator": group.logical_time_numerator,
                    "ordered_set_transitions": [
                        {
                            "after": transition.after,
                            "before": transition.before,
                            "cause": transition.cause,
                            "column": transition.column,
                            "row": transition.row,
                        }
                        for transition in group.transitions
                    ],
                }
                for group in frozen_groups
            ],
            "rows": rows,
            "scale": scale,
            "schema_version": _EVENT_TRACE_SCHEMA,
        }
    )
    return RouteASyntheticTrace(
        suite_role=suite_role,
        scale=scale,  # type: ignore[arg-type]
        formal_seed=formal_seed,
        rows=rows,
        columns=_COLUMNS,
        initial_nonzeros=initial_nonzeros,
        initial_state_bytes=initial_state_bytes,
        initial_state_sha256=initial_state_sha256,
        accepted_groups=frozen_groups,
        event_trace_bytes=event_trace_bytes,
        event_trace_sha256=hashlib.sha256(event_trace_bytes).hexdigest(),
    )
