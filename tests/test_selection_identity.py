from __future__ import annotations

from typing import get_args

from dynamic_cssc.selection import CandidateStrategy, build_fixed_candidates
from dynamic_cssc.strategy_state import STRATEGIES


def test_strong_reference_identity_is_available_only_to_candidate_registration() -> None:
    strong_strategy = "Packed-COO-Cloud-Segmented-Delta"

    assert strong_strategy in get_args(CandidateStrategy)
    assert strong_strategy not in STRATEGIES


def test_packed_coo_candidate_uses_client_lane_identity_and_actual_capacity() -> None:
    candidates = build_fixed_candidates(
        reserved_slack_betas=[0, 0.05, 0.10, 0.20, 0.40],
        periodic_repack_windows=[1, 4, 16, 64],
    )

    packed_coo = next(
        candidate for candidate in candidates if candidate.packed_coo_segment_capacity is not None
    )

    assert packed_coo.strategy == "Packed-COO-Client-Lane-Delta"
    assert packed_coo.candidate_id == "packed-coo-client-lane-delta/capacity=128"
    assert all("HYB" not in candidate.strategy for candidate in candidates)
    assert all("hyb" not in candidate.candidate_id for candidate in candidates)


def test_legacy_fixed_candidate_roster_and_order_remain_exact() -> None:
    candidates = build_fixed_candidates(
        reserved_slack_betas=[0, 0.05, 0.10, 0.20, 0.40],
        periodic_repack_windows=[1, 4, 16, 64],
    )

    assert tuple(candidate.candidate_id for candidate in candidates) == (
        "padding-reuse",
        "mini-cssc-delta",
        "packed-coo-client-lane-delta/capacity=128",
        "strict-local-repack",
        "reserved-slack/beta=0",
        "reserved-slack/beta=0.05",
        "reserved-slack/beta=0.1",
        "reserved-slack/beta=0.2",
        "reserved-slack/beta=0.4",
        "periodic-repack/windows=1",
        "periodic-repack/windows=4",
        "periodic-repack/windows=16",
        "periodic-repack/windows=64",
    )
    assert all(candidate.strategy != "Packed-COO-Cloud-Segmented-Delta" for candidate in candidates)
