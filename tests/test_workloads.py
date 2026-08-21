from __future__ import annotations

import pytest

from dynamic_cssc.events import EventKind
from dynamic_cssc.workloads import generate_event_stream, generate_initial_matrix


@pytest.mark.parametrize(
    "workload",
    [
        "zipf",
        "migrating-hotspot",
        "single-row-hotspot",
        "multi-row-hotspot",
        "bursty",
        "mixed-insert-delete-modify",
        "repeated-coordinate",
    ],
)
def test_generated_stream_never_leaves_frozen_matrix_value_domain(workload: str) -> None:
    bound = 7
    initial = generate_initial_matrix(
        32,
        32,
        4,
        seed=20260822,
        matrix_entry_abs_bound=bound,
    )

    events = generate_event_stream(
        workload,
        initial,
        rows=32,
        cols=32,
        update_count=2048,
        seed=20260823,
        query_every=0,
        matrix_entry_abs_bound=bound,
    )

    state = dict(initial)
    for event in events:
        assert event.kind == EventKind.SET
        assert event.row is not None and event.col is not None and event.value is not None
        assert abs(event.value) <= bound
        if event.value == 0:
            state.pop((event.row, event.col), None)
        else:
            state[(event.row, event.col)] = event.value
        assert all(abs(value) <= bound for value in state.values())


def test_stream_rejects_an_initial_state_outside_the_frozen_domain() -> None:
    with pytest.raises(ValueError, match="matrix_entry_abs_bound"):
        generate_event_stream(
            "zipf",
            {(0, 0): 8},
            rows=1,
            cols=2,
            update_count=1,
            seed=1,
            query_every=0,
            matrix_entry_abs_bound=7,
        )
