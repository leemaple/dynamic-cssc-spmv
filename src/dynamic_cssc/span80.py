from __future__ import annotations

from math import ceil


def _prune_dominated(states: dict[int, int]) -> dict[int, int]:
    """Keep only (selected rows, covered weight) Pareto-frontier states."""

    frontier: dict[int, int] = {}
    best_weight = -1
    for selected, covered_weight in sorted(states.items()):
        if covered_weight > best_weight:
            frontier[selected] = covered_weight
            best_weight = covered_weight
    return frontier


def _sparse_minimum_selected_rows(
    positive_rows: list[tuple[int, int]],
    row_count: int,
    max_intervals: int,
    target: int,
) -> list[int]:
    """Solve on positive rows while accounting for zero-row gaps exactly."""

    outside: list[dict[int, int]] = [dict() for _ in range(max_intervals + 1)]
    inside: list[dict[int, int]] = [dict() for _ in range(max_intervals + 1)]
    outside[0][0] = 0
    previous_position = positive_rows[0][0]

    for position, weight in positive_rows:
        distance = position - previous_position
        next_outside: list[dict[int, int]] = [
            dict() for _ in range(max_intervals + 1)
        ]
        next_inside: list[dict[int, int]] = [
            dict() for _ in range(max_intervals + 1)
        ]
        for interval_count in range(max_intervals + 1):
            for selected, covered_weight in outside[interval_count].items():
                next_outside[interval_count][selected] = max(
                    next_outside[interval_count].get(selected, -1), covered_weight
                )
                if interval_count < max_intervals:
                    next_inside[interval_count + 1][selected + 1] = max(
                        next_inside[interval_count + 1].get(selected + 1, -1),
                        min(target, covered_weight + weight),
                    )
            for selected, covered_weight in inside[interval_count].items():
                next_outside[interval_count][selected] = max(
                    next_outside[interval_count].get(selected, -1), covered_weight
                )
                continued_length = selected + distance
                next_inside[interval_count][continued_length] = max(
                    next_inside[interval_count].get(continued_length, -1),
                    min(target, covered_weight + weight),
                )
                if interval_count < max_intervals:
                    next_inside[interval_count + 1][selected + 1] = max(
                        next_inside[interval_count + 1].get(selected + 1, -1),
                        min(target, covered_weight + weight),
                    )
        outside = [_prune_dominated(states) for states in next_outside]
        inside = [_prune_dominated(states) for states in next_inside]
        previous_position = position

    best_by_limit = [row_count] * (max_intervals + 1)
    best_so_far = row_count
    for interval_count in range(1, max_intervals + 1):
        best_exact = min(
            (
                selected
                for states in (outside[interval_count], inside[interval_count])
                for selected, covered_weight in states.items()
                if covered_weight >= target
            ),
            default=row_count,
        )
        best_so_far = min(best_so_far, best_exact)
        best_by_limit[interval_count] = best_so_far
    return best_by_limit


def _dense_minimum_selected_rows(
    weights: list[int], max_intervals: int, target: int
) -> list[int]:
    """Dense reference DP, bounded to states reachable in the consumed prefix."""

    row_count = len(weights)
    negative = -10**30

    # outside[k][l] and inside[k][l] after consuming a prefix.
    outside = [[negative] * (row_count + 1) for _ in range(max_intervals + 1)]
    inside = [[negative] * (row_count + 1) for _ in range(max_intervals + 1)]
    outside[0][0] = 0

    for position, weight in enumerate(weights):
        next_outside = [
            [negative] * (row_count + 1) for _ in range(max_intervals + 1)
        ]
        next_inside = [
            [negative] * (row_count + 1) for _ in range(max_intervals + 1)
        ]
        reachable_intervals = min(max_intervals, position + 1)
        for interval_count in range(reachable_intervals + 1):
            for selected in range(position + 1):
                best_out = max(
                    outside[interval_count][selected],
                    inside[interval_count][selected],
                )
                if best_out > next_outside[interval_count][selected]:
                    next_outside[interval_count][selected] = best_out
                if inside[interval_count][selected] != negative:
                    value = min(target, inside[interval_count][selected] + weight)
                    if value > next_inside[interval_count][selected + 1]:
                        next_inside[interval_count][selected + 1] = value
                if (
                    interval_count < max_intervals
                    and outside[interval_count][selected] != negative
                ):
                    value = min(target, outside[interval_count][selected] + weight)
                    if value > next_inside[interval_count + 1][selected + 1]:
                        next_inside[interval_count + 1][selected + 1] = value
        outside, inside = next_outside, next_inside

    best_by_limit = [row_count] * (max_intervals + 1)
    best_so_far = row_count
    for interval_count in range(1, max_intervals + 1):
        best_exact = next(
            (
                selected
                for selected in range(row_count + 1)
                if max(
                    outside[interval_count][selected],
                    inside[interval_count][selected],
                )
                >= target
            ),
            row_count,
        )
        best_so_far = min(best_so_far, best_exact)
        best_by_limit[interval_count] = best_so_far
    return best_by_limit


def _minimum_selected_rows_by_interval_limit(
    weights: list[int], max_intervals: int, target: int
) -> tuple[list[int], int]:
    positive_rows = [(index, weight) for index, weight in enumerate(weights) if weight]
    effective_intervals = min(max_intervals, len(positive_rows))

    # The dictionary frontier avoids the dense DP's selected-length axis when zero rows
    # dominate. Empirical crossover is above 50% density, so this conservative split
    # keeps the sparse path bounded without slowing dense inputs.
    if len(positive_rows) * 2 <= len(weights):
        best_by_limit = _sparse_minimum_selected_rows(
            positive_rows,
            len(weights),
            effective_intervals,
            target,
        )
    else:
        best_by_limit = _dense_minimum_selected_rows(
            weights,
            effective_intervals,
            target,
        )
    return best_by_limit, effective_intervals


def minimum_span_fraction(
    weights: list[int], max_intervals: int, target_fraction: float = 0.8
) -> float:
    """Minimum selected-row fraction covering the target weight with <= K intervals.

    Dynamic programming chooses up to ``max_intervals`` disjoint contiguous intervals and
    minimizes their total number of rows. This is the unconstrained diagnostic; a later F2
    implementation may additionally restrict intervals to aligned power-of-two slices.
    """

    if not weights:
        return 0.0
    if max_intervals <= 0:
        raise ValueError("max_intervals must be positive")
    if not 0 < target_fraction <= 1:
        raise ValueError("target_fraction must be in (0, 1]")
    if any(weight < 0 for weight in weights):
        raise ValueError("weights must be nonnegative")

    total = sum(weights)
    if total == 0:
        return 0.0
    target = ceil(total * target_fraction)
    best_by_limit, effective_intervals = _minimum_selected_rows_by_interval_limit(
        weights, max_intervals, target
    )
    return best_by_limit[effective_intervals] / len(weights)


def span80_curve(
    weights: list[int], interval_counts: tuple[int, ...] = (1, 2, 4, 8)
) -> dict[int, float]:
    if not interval_counts:
        return {}
    if not weights:
        return {count: 0.0 for count in interval_counts}
    if any(count <= 0 for count in interval_counts):
        raise ValueError("max_intervals must be positive")
    if any(weight < 0 for weight in weights):
        raise ValueError("weights must be nonnegative")

    total = sum(weights)
    if total == 0:
        return {count: 0.0 for count in interval_counts}
    target = ceil(total * 0.8)
    best_by_limit, effective_intervals = _minimum_selected_rows_by_interval_limit(
        weights, max(interval_counts), target
    )
    return {
        count: best_by_limit[min(count, effective_intervals)] / len(weights)
        for count in interval_counts
    }
