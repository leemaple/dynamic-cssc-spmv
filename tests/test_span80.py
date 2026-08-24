from __future__ import annotations

import builtins
from itertools import product
from math import ceil

import pytest

import dynamic_cssc.span80 as span80_module
from dynamic_cssc.span80 import minimum_span_fraction, span80_curve


def _brute_force_minimum_span_fraction(
    weights: tuple[int, ...], max_intervals: int, target_fraction: float
) -> float:
    if not weights or sum(weights) == 0:
        return 0.0
    target = ceil(sum(weights) * target_fraction)
    best = len(weights)
    for mask in range(1 << len(weights)):
        intervals = 0
        previous_selected = False
        covered = 0
        selected = 0
        for index, weight in enumerate(weights):
            is_selected = bool(mask & (1 << index))
            if is_selected and not previous_selected:
                intervals += 1
            if is_selected:
                covered += weight
                selected += 1
            previous_selected = is_selected
        if intervals <= max_intervals and covered >= target:
            best = min(best, selected)
    return best / len(weights)


def test_concentrated_hotspot_needs_small_span() -> None:
    weights = [0] * 100
    for index in range(10, 20):
        weights[index] = 10
    assert minimum_span_fraction(weights, 1) <= 0.10


def test_two_separated_hotspots_benefit_from_two_intervals() -> None:
    weights = [0] * 100
    for index in range(5, 10):
        weights[index] = 10
    for index in range(80, 85):
        weights[index] = 10
    one = minimum_span_fraction(weights, 1)
    two = minimum_span_fraction(weights, 2)
    assert two < one
    assert two <= 0.10


def test_zero_overflow_curve_is_zero() -> None:
    assert span80_curve([0] * 16) == {1: 0.0, 2: 0.0, 4: 0.0, 8: 0.0}


@pytest.mark.parametrize("target_fraction", [0.5, 0.8, 1.0])
def test_minimum_span_matches_exhaustive_small_domain(target_fraction: float) -> None:
    for length in range(1, 7):
        for weights in product((0, 1, 2), repeat=length):
            for max_intervals in range(1, min(3, length) + 1):
                assert minimum_span_fraction(
                    list(weights), max_intervals, target_fraction
                ) == _brute_force_minimum_span_fraction(
                    weights, max_intervals, target_fraction
                )


def test_sparse_curve_uses_a_bounded_iteration_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    visited_range_values = 0

    def counted_range(*args: int) -> range:
        nonlocal visited_range_values
        values = builtins.range(*args)
        visited_range_values += len(values)
        return values

    monkeypatch.setattr(span80_module, "range", counted_range, raising=False)
    weights = [0] * 512
    weights[257] = 1

    assert span80_curve(weights) == {
        1: 1 / 512,
        2: 1 / 512,
        4: 1 / 512,
        8: 1 / 512,
    }
    assert visited_range_values < 10_000
