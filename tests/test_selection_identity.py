from __future__ import annotations

from dynamic_cssc.selection import build_fixed_candidates


def test_packed_coo_candidate_uses_client_lane_identity_and_actual_capacity() -> None:
    candidates = build_fixed_candidates(
        reserved_slack_betas=[0, 0.05, 0.10, 0.20, 0.40],
        periodic_repack_windows=[1, 4, 16, 64],
    )

    packed_coo = next(
        candidate
        for candidate in candidates
        if candidate.packed_coo_segment_capacity is not None
    )

    assert packed_coo.strategy == "Packed-COO-Client-Lane-Delta"
    assert packed_coo.candidate_id == "packed-coo-client-lane-delta/capacity=128"
    assert all("HYB" not in candidate.strategy for candidate in candidates)
    assert all("hyb" not in candidate.candidate_id for candidate in candidates)
