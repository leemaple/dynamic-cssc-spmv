from __future__ import annotations

from math import ceil


def minimum_span_fraction(weights: list[int], max_intervals: int, target_fraction: float = 0.8) -> float:
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
    n = len(weights)
    negative = -10**30

    # outside[k][l] and inside[k][l] after consuming a prefix.
    outside = [[negative] * (n + 1) for _ in range(max_intervals + 1)]
    inside = [[negative] * (n + 1) for _ in range(max_intervals + 1)]
    outside[0][0] = 0

    for weight in weights:
        next_outside = [[negative] * (n + 1) for _ in range(max_intervals + 1)]
        next_inside = [[negative] * (n + 1) for _ in range(max_intervals + 1)]
        for k in range(max_intervals + 1):
            for selected in range(n + 1):
                best_out = max(outside[k][selected], inside[k][selected])
                if best_out > next_outside[k][selected]:
                    next_outside[k][selected] = best_out
                if selected == n:
                    continue
                if inside[k][selected] != negative:
                    value = inside[k][selected] + weight
                    if value > next_inside[k][selected + 1]:
                        next_inside[k][selected + 1] = value
                if k < max_intervals and outside[k][selected] != negative:
                    value = outside[k][selected] + weight
                    if value > next_inside[k + 1][selected + 1]:
                        next_inside[k + 1][selected + 1] = value
        outside, inside = next_outside, next_inside

    for selected in range(n + 1):
        best = max(
            max(outside[k][selected], inside[k][selected])
            for k in range(max_intervals + 1)
        )
        if best >= target:
            return selected / n
    return 1.0


def span80_curve(weights: list[int], interval_counts: tuple[int, ...] = (1, 2, 4, 8)) -> dict[int, float]:
    return {count: minimum_span_fraction(weights, count, 0.8) for count in interval_counts}
