from __future__ import annotations

import random
from collections.abc import Iterable

from .events import Event


def generate_initial_matrix(
    rows: int,
    cols: int,
    nnz_per_row: int,
    *,
    seed: int,
    matrix_entry_abs_bound: int = 7,
) -> dict[tuple[int, int], int]:
    if not 0 <= nnz_per_row <= cols:
        raise ValueError("nnz_per_row must be in [0, cols]")
    if (
        not isinstance(matrix_entry_abs_bound, int)
        or isinstance(matrix_entry_abs_bound, bool)
        or matrix_entry_abs_bound < 1
    ):
        raise ValueError("matrix_entry_abs_bound must be a positive integer")
    rng = random.Random(seed)
    state: dict[tuple[int, int], int] = {}
    for row in range(rows):
        for col in rng.sample(range(cols), nnz_per_row):
            state[(row, col)] = rng.randint(1, matrix_entry_abs_bound)
    return state


def _weighted_row(rng: random.Random, rows: int, exponent: float = 1.2) -> int:
    weights = [1.0 / ((rank + 1) ** exponent) for rank in range(rows)]
    return rng.choices(range(rows), weights=weights, k=1)[0]


def _existing_in_row(state: dict[tuple[int, int], int], row: int) -> list[int]:
    return [col for (candidate_row, col), value in state.items() if candidate_row == row and value]


def _new_column(
    rng: random.Random,
    state: dict[tuple[int, int], int],
    row: int,
    cols: int,
) -> int | None:
    for _ in range(min(cols * 2, 2048)):
        col = rng.randrange(cols)
        if (row, col) not in state:
            return col
    available = [col for col in range(cols) if (row, col) not in state]
    return rng.choice(available) if available else None


def _bounded_modified_value(
    rng: random.Random,
    current: int,
    matrix_entry_abs_bound: int,
) -> int:
    candidates = [
        current + delta
        for delta in (-1, 1, 2)
        if current + delta != 0
        and abs(current + delta) <= matrix_entry_abs_bound
    ]
    return rng.choice(candidates) if candidates else current


def generate_event_stream(
    workload: str,
    initial_state: dict[tuple[int, int], int],
    *,
    rows: int,
    cols: int,
    update_count: int,
    seed: int,
    query_every: int = 32,
    matrix_entry_abs_bound: int = 7,
) -> list[Event]:
    """Generate deterministic skewed update/query streams for CI smoke tests."""

    if update_count <= 0:
        raise ValueError("update_count must be positive")
    if (
        not isinstance(matrix_entry_abs_bound, int)
        or isinstance(matrix_entry_abs_bound, bool)
        or matrix_entry_abs_bound < 1
    ):
        raise ValueError("matrix_entry_abs_bound must be a positive integer")
    if any(abs(value) > matrix_entry_abs_bound for value in initial_state.values()):
        raise ValueError("initial state exceeds matrix_entry_abs_bound")
    rng = random.Random(seed)
    state = dict(initial_state)
    events: list[Event] = []
    repeated_pool = [(row, col) for row, col in list(state)[: min(16, len(state))]]
    timestamp = 0.0

    for index in range(update_count):
        phase = index / update_count
        if workload == "zipf":
            row = _weighted_row(rng, rows)
        elif workload == "migrating-hotspot":
            center = int(phase * 4) * max(1, rows // 4)
            row = (center + rng.randrange(max(1, rows // 32))) % rows
        elif workload == "single-row-hotspot":
            row = 0 if rng.random() < 0.9 else rng.randrange(rows)
        elif workload == "multi-row-hotspot":
            row = rng.randrange(min(8, rows)) if rng.random() < 0.9 else rng.randrange(rows)
        elif workload == "bursty":
            in_burst = (index // max(1, update_count // 10)) % 2 == 0
            row = _weighted_row(rng, rows, 1.5) if in_burst else rng.randrange(rows)
        elif workload == "repeated-coordinate" and repeated_pool:
            row, col = rng.choice(repeated_pool)
            new_value = _bounded_modified_value(
                rng,
                state.get((row, col), 0),
                matrix_entry_abs_bound,
            )
            state[(row, col)] = new_value
            events.append(Event.set(timestamp, row, col, new_value))
            timestamp += 0.01
            if query_every and (index + 1) % query_every == 0:
                events.append(Event.query(timestamp))
                timestamp += 0.001
            continue
        else:
            row = rng.randrange(rows)

        existing = _existing_in_row(state, row)
        selector = rng.random()
        if workload == "mixed-insert-delete-modify":
            insert_cutoff, modify_cutoff = 0.45, 0.8
        else:
            insert_cutoff, modify_cutoff = 0.6, 0.9

        if selector < insert_cutoff:
            col = _new_column(rng, state, row, cols)
            if col is None and existing:
                col = rng.choice(existing)
                value = _bounded_modified_value(
                    rng,
                    state[(row, col)],
                    matrix_entry_abs_bound,
                )
            elif col is None:
                continue
            else:
                value = rng.randint(1, matrix_entry_abs_bound)
            state[(row, col)] = value
        elif selector < modify_cutoff and existing:
            col = rng.choice(existing)
            value = _bounded_modified_value(
                rng,
                state[(row, col)],
                matrix_entry_abs_bound,
            )
            state[(row, col)] = value
        elif existing:
            col = rng.choice(existing)
            value = 0
            state.pop((row, col), None)
        else:
            col = _new_column(rng, state, row, cols)
            if col is None:
                continue
            value = rng.randint(1, matrix_entry_abs_bound)
            state[(row, col)] = value

        events.append(Event.set(timestamp, row, col, value))
        timestamp += 0.01
        if query_every and (index + 1) % query_every == 0:
            events.append(Event.query(timestamp))
            timestamp += 0.001

    return events


def event_rows(events: Iterable[Event]) -> list[int]:
    return [event.row for event in events if event.row is not None]
