from __future__ import annotations

from dynamic_cssc.events import NetUpdate, PublicationWindow
from dynamic_cssc.strategy_state import STRATEGIES, advance_publication, initialize_strategy


def test_packed_coo_client_lane_identity_preserves_the_packed_coo_transition() -> None:
    strategy = "Packed-COO-Client-Lane-Delta"
    assert strategy in STRATEGIES
    assert all("HYB" not in candidate for candidate in STRATEGIES)
    state = initialize_strategy(
        strategy,
        {(0, 0): 1, (1, 0): 2},
        rows=2,
        cols=4,
        effective_slots=2,
        partition_rows=2,
        max_row_nnz=4,
        packed_coo_segment_capacity=2,
    )
    window = PublicationWindow(
        index=0,
        start_time=0,
        end_time=0,
        updates=(NetUpdate(0, 3, 0, 4),),
        query_count=1,
        reason="query",
    )

    transition = advance_publication(state, window)

    assert transition.state.strategy == strategy
    assert transition.facts.overflow == 1
    assert len(transition.state.coo_segments) == 1
    assert transition.facts.active_component_ids == ("base", "packed-coo-delta")
