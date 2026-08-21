from __future__ import annotations

from dynamic_cssc.events import Event, publication_windows


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
    assert windows[0].updates == ()
