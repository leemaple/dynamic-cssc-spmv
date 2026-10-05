from collections import Counter

import pytest

from dynamic_cssc.r1_workloads import (
    COLS,
    WINDOWS,
    _generate,
    balanced_strategy_order,
    calibration_workload,
)


@pytest.mark.parametrize("rows", [256, 1024])
@pytest.mark.parametrize("distribution", ["concentrated", "dispersed"])
def test_query_intensity_pairs_each_window_not_global_prefix(rows, distribution):
    low = calibration_workload(rows=rows, distribution=distribution, queries_per_window=1)
    high = calibration_workload(rows=rows, distribution=distribution, queries_per_window=8)
    assert low.initial == high.initial and low.windows == high.windows
    assert len(low.initial) == rows * 8
    assert len(low.windows) == WINDOWS
    for lower, higher in zip(low.queries, high.queries, strict=True):
        assert len(lower) == 1 and len(higher) == 8
        assert lower[0] == higher[0]
        assert len(lower[0]) == COLS
    # The second window's low query is not window 0's second high query.
    assert low.queries[1][0] != high.queries[0][1]
    domain_rows = rows // 16 if distribution == "concentrated" else rows
    logical = {(r, c): v for r, c, v in low.initial}
    for updates in low.windows:
        counts = Counter()
        assert len({(u.row, u.col) for u in updates}) == len(updates)
        for u in updates:
            assert 0 <= u.row < domain_rows
            assert logical.get((u.row, u.col), 0) == u.before
            assert u.before != u.after
            counts["insert" if not u.before else "delete" if not u.after else "modify"] += 1
            if u.after:
                logical[u.row, u.col] = u.after
            else:
                del logical[u.row, u.col]
        assert counts == {"modify": rows // 32, "delete": rows // 32, "insert": rows // 16}
    assert len(logical) == rows * 8 + rows // 4
    assert sum(len(w) for w in low.windows) == rows


def test_six_orders_have_equal_counts_and_positions():
    orders = [balanced_strategy_order(g, r) for g in range(24) for r in range(3)]
    assert sorted(Counter(orders).values()) == [12] * 6
    for position in range(3):
        assert Counter(order[position] for order in orders) == {
            "repack": 24,
            "padding": 24,
            "strong": 24,
        }


@pytest.mark.parametrize(
    "kwargs",
    [
        {"rows": 512},
        {"queries_per_window": 2},
        {"distribution": "choose-fastest"},
    ],
)
def test_illegal_factors_cannot_expand_or_search_the_grid(kwargs):
    args = {"rows": 256, "distribution": "dispersed", "queries_per_window": 1, **kwargs}
    with pytest.raises(ValueError):
        calibration_workload(**args)


def test_unfrozen_generator_cannot_generate_formal_seed_inputs():
    with pytest.raises(ValueError, match="no formal inputs"):
        _generate(rows=256, distribution="dispersed", queries_per_window=1, identity="formal-1")
