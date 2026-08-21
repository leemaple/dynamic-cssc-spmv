from __future__ import annotations

from dynamic_cssc.span80 import minimum_span_fraction, span80_curve


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
