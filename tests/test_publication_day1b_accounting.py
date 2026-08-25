from __future__ import annotations

from dataclasses import replace
from decimal import Decimal
from fractions import Fraction

import pytest

from dynamic_cssc.day1_registry import RegisteredCandidate
from dynamic_cssc.day2_calibration_authority import PRIMITIVE_NAMES
from dynamic_cssc.publication_day1b_accounting import (
    DAY1B_ACCOUNTING_EXECUTION_BASIS,
    Day1BAccountingDomain,
    Day1BQueryWindowAccounting,
    PublicationDay1BAccountingError,
    replay_publication_day1b_candidate_cell,
)
from dynamic_cssc.publication_schedule import ExactPublicationWindow, ScheduledNetUpdate


def _domain(*, effective_slots: int = 4, partition_rows: int = 2) -> Day1BAccountingDomain:
    return Day1BAccountingDomain(
        rows=4,
        cols=4,
        effective_slots=effective_slots,
        partition_rows=partition_rows,
        matrix_value_bound=7,
        max_row_nnz=4,
        strong_segment_width=4,
    )


def _window(
    index: int,
    phase: str,
    update: tuple[int, int, int, int],
    *,
    query_count: int,
) -> ExactPublicationWindow:
    return ExactPublicationWindow(
        index=index,
        phase=phase,
        accepted_group_start=index,
        accepted_group_end=index + 1,
        start_time=Fraction(index, 10),
        end_time=Fraction(index + 1, 10),
        set_count=1,
        updates=(ScheduledNetUpdate(*update),),
        query_count=query_count,
        reason="query" if query_count else "phase-boundary:warmup",
    )


def _reserved_candidate() -> RegisteredCandidate:
    return RegisteredCandidate(
        candidate_id="reserved-slack/beta=0.4",
        strategy="ReservedSlack-CSSC",
        role="reference",
        reserved_slack_beta=Decimal("0.4"),
    )


def _strong_candidate() -> RegisteredCandidate:
    return RegisteredCandidate(
        candidate_id="packed-coo-cloud-segmented-delta/segment-width=128",
        strategy="Packed-COO-Cloud-Segmented-Delta",
        role="reference",
        reserved_slack_beta=Decimal("0"),
    )


def test_weighted_replay_advances_state_once_and_streams_one_plan_per_window() -> None:
    windows = (
        _window(0, "warmup", (0, 0, 0, 1), query_count=0),
        _window(1, "tuning", (0, 1, 0, 2), query_count=1_000_000),
        _window(2, "heldout", (0, 0, 1, 0), query_count=2),
    )
    descriptors: list[Day1BQueryWindowAccounting] = []

    result = replay_publication_day1b_candidate_cell(
        candidate=_reserved_candidate(),
        windows=iter(windows),
        domain=_domain(),
        query_window_sink=descriptors.append,
    )

    assert result.realized_window_count == 3
    assert result.realized_query_window_count == 2
    assert result.realized_query_count == 1_000_002
    assert result.terminal_version_id == "v00000003"
    assert result.state_reset_count == 0
    assert [phase.phase for phase in result.phases] == [
        "warmup",
        "tuning-prefix",
        "held-out",
    ]
    assert [descriptor.query_count for descriptor in descriptors] == [1_000_000, 2]
    assert [descriptor.first_global_query_ordinal for descriptor in descriptors] == [
        0,
        1_000_000,
    ]
    assert [descriptor.query_plan.version_id for descriptor in descriptors] == [
        "v00000002",
        "v00000003",
    ]
    assert all(descriptor.query_plan.returned_share_count == 2 for descriptor in descriptors)
    assert all(descriptor.query_plan.random_route_count == 0 for descriptor in descriptors)
    tuning = result.phases[1]
    assert tuning.realized_query_count == 1_000_000
    assert tuning.query_window_count == 1
    assert tuning.query_primitive_counts[PRIMITIVE_NAMES.index("encrypt")] == 3_000_000
    document = result.to_document()
    assert document["execution_basis"] == DAY1B_ACCOUNTING_EXECUTION_BASIS
    assert document["accounting_sha256"] == result.accounting_sha256


def test_replay_is_deterministic_and_does_not_retain_query_descriptors() -> None:
    windows = (
        _window(0, "warmup", (0, 0, 0, 1), query_count=0),
        _window(1, "tuning", (0, 1, 0, 2), query_count=7),
        _window(2, "heldout", (0, 0, 1, 0), query_count=11),
    )

    first = replay_publication_day1b_candidate_cell(
        candidate=_reserved_candidate(), windows=iter(windows), domain=_domain()
    )
    second = replay_publication_day1b_candidate_cell(
        candidate=_reserved_candidate(), windows=iter(windows), domain=_domain()
    )

    assert first == second
    assert first.accounting_sha256 == second.accounting_sha256
    assert "query_windows" not in first.to_document()
    assert sum(phase.query_window_count for phase in first.phases) == 2


def test_no_update_window_does_not_publish_a_new_version() -> None:
    windows = (
        _window(0, "warmup", (0, 0, 0, 1), query_count=0),
        replace(
            _window(1, "tuning", (0, 1, 0, 2), query_count=7),
            set_count=0,
            updates=(),
        ),
        _window(2, "heldout", (0, 0, 1, 3), query_count=11),
    )

    result = replay_publication_day1b_candidate_cell(
        candidate=_reserved_candidate(), windows=windows, domain=_domain()
    )

    assert result.terminal_version_id == "v00000002"
    assert [
        phase.realized_version_publication_count for phase in result.phases
    ] == [1, 0, 1]


def test_multiple_updates_in_one_window_publish_exactly_one_version() -> None:
    warmup = replace(
        _window(0, "warmup", (0, 0, 0, 1), query_count=0),
        set_count=2,
        updates=(
            ScheduledNetUpdate(0, 0, 0, 1),
            ScheduledNetUpdate(0, 1, 0, 2),
        ),
    )
    windows = (
        warmup,
        _window(1, "tuning", (1, 0, 0, 2), query_count=7),
        _window(2, "heldout", (1, 1, 0, 3), query_count=11),
    )

    result = replay_publication_day1b_candidate_cell(
        candidate=_reserved_candidate(), windows=windows, domain=_domain()
    )

    assert result.phases[0].realized_net_update_count == 2
    assert result.phases[0].realized_version_publication_count == 1
    assert result.terminal_version_id == "v00000003"


def test_strong_replay_classifies_uniform_dummy_routes_before_weighting() -> None:
    domain = Day1BAccountingDomain(
        rows=2,
        cols=4,
        effective_slots=128,
        partition_rows=1,
        matrix_value_bound=7,
        max_row_nnz=4,
        strong_segment_width=128,
    )
    windows = (
        _window(0, "warmup", (0, 0, 0, 1), query_count=0),
        _window(1, "tuning", (1, 0, 0, 2), query_count=3),
        _window(2, "heldout", (0, 1, 0, 3), query_count=5),
    )
    descriptors: list[Day1BQueryWindowAccounting] = []

    result = replay_publication_day1b_candidate_cell(
        candidate=_strong_candidate(),
        windows=windows,
        domain=domain,
        query_window_sink=descriptors.append,
    )

    assert result.terminal_version_id == "v00000003"
    assert [descriptor.query_plan.returned_share_count for descriptor in descriptors] == [2, 2]
    assert [descriptor.query_plan.random_route_count for descriptor in descriptors] == [0, 0]
    assert [descriptor.query_plan.dummy_route_count for descriptor in descriptors] == [2, 2]
    tuning = result.phases[1]
    assert tuning.query_primitive_counts[PRIMITIVE_NAMES.index("encrypt")] == 12


def test_replay_rejects_phase_regression_before_minting_a_result() -> None:
    windows = (
        _window(0, "warmup", (0, 0, 0, 1), query_count=0),
        _window(1, "heldout", (0, 1, 0, 2), query_count=1),
        _window(2, "tuning", (0, 2, 0, 3), query_count=1),
    )

    with pytest.raises(PublicationDay1BAccountingError, match="phases cannot regress"):
        replay_publication_day1b_candidate_cell(
            candidate=_reserved_candidate(), windows=windows, domain=_domain()
        )


def test_replay_rejects_a_retargeted_candidate_policy() -> None:
    candidate = replace(_reserved_candidate(), candidate_id="reserved-slack/beta=0.2")

    with pytest.raises(PublicationDay1BAccountingError, match="frozen Day 1 policy"):
        replay_publication_day1b_candidate_cell(
            candidate=candidate,
            windows=(),
            domain=_domain(),
        )
