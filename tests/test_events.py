from __future__ import annotations

import pytest

from dynamic_cssc.events import Event, publication_windows


def test_query_only_burst_is_preserved_as_one_window() -> None:
    windows = list(
        publication_windows(
            [Event.query(1.0), Event.query(1.0), Event.query(1.0)],
            max_seconds=10.0,
            microbatch_max_updates=100,
        )
    )

    assert len(windows) == 1
    assert windows[0].updates == ()
    assert windows[0].query_count == 3
    assert windows[0].reason == "query"


def test_out_of_order_events_are_rejected_instead_of_sorted() -> None:
    events = [Event.set(2.0, 0, 0, 1), Event.query(1.0)]

    with pytest.raises(ValueError, match="nondecreasing"):
        list(
            publication_windows(
                events,
                max_seconds=10.0,
                microbatch_max_updates=100,
            )
        )


def test_net_merge_stays_inside_query_boundary() -> None:
    initial = {(0, 0): 1}
    events = [
        Event.set(0.0, 0, 0, 2),
        Event.set(0.1, 0, 0, 3),
        Event.query(0.2),
        Event.set(0.3, 0, 0, 4),
        Event.query(0.4),
    ]
    windows = list(
        publication_windows(
            events,
            initial,
            max_seconds=10.0,
            microbatch_max_updates=100,
            query_requires_latest=True,
        )
    )
    assert len(windows) == 2
    assert [window.query_count for window in windows] == [1, 1]
    assert windows[0].updates[0].before == 1
    assert windows[0].updates[0].after == 3
    assert windows[1].updates[0].before == 3
    assert windows[1].updates[0].after == 4


def test_noop_disappears_within_one_window() -> None:
    initial = {(0, 0): 5}
    events = [Event.set(0.0, 0, 0, 8), Event.set(0.1, 0, 0, 5), Event.query(0.2)]
    windows = list(
        publication_windows(
            events,
            initial,
            max_seconds=10.0,
            microbatch_max_updates=100,
        )
    )
    assert len(windows) == 1
    assert windows[0].query_count == 1
    assert windows[0].updates == ()


def test_microbatch_boundary_does_not_split_same_timestamp_atomic_sets() -> None:
    windows = list(
        publication_windows(
            [
                Event.set(1.0, 0, 0, 0),
                Event.set(1.0, 0, 1, 1),
                Event.query(1.0),
            ],
            {(0, 0): 1},
            max_seconds=10.0,
            microbatch_max_updates=1,
        )
    )

    assert len(windows) == 1
    assert [(update.col, update.before, update.after) for update in windows[0].updates] == [
        (0, 1, 0),
        (1, 0, 1),
    ]
    assert windows[0].query_count == 1
    assert windows[0].reason == "query"
