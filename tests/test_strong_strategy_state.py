from __future__ import annotations

import copy
import os
import subprocess
import sys
from dataclasses import fields, replace
from pathlib import Path

import pytest

from dynamic_cssc.events import NetUpdate, PublicationWindow
from dynamic_cssc.strategy_state import (
    StrongStrategyConfig,
    StrongStrategyState,
    StrongTransition,
    advance_strong_publication,
    decode_strong_state,
    initialize_strong_strategy,
)
from dynamic_cssc.strong_execution import compile_strong_execution


def _window(
    *updates: NetUpdate, index: int = 0, queries: int = 1
) -> PublicationWindow:
    return PublicationWindow(
        index=index,
        start_time=float(index),
        end_time=float(index),
        updates=tuple(updates),
        query_count=queries,
        reason="query",
    )


def test_strong_snapshot_is_independent_and_query_only_compiles_without_advancing() -> None:
    logical = {(0, 0): 2, (1, 1): -3}
    state = initialize_strong_strategy(
        logical,
        rows=2,
        cols=6,
        effective_slots=4,
        partition_rows=2,
        matrix_value_bound=7,
        max_row_nnz=6,
        segment_width=2,
    )

    assert type(state) is StrongStrategyState
    assert not hasattr(state, "coo_segments")
    assert state.version_ordinal == 0
    assert decode_strong_state(state) == logical

    transition = advance_strong_publication(state, _window(index=7, queries=3))

    assert transition.state is state
    assert transition.state.version_ordinal == 0
    assert transition.facts.updates == 0
    assert transition.facts.query_count == 3
    assert transition.execution_bundle == compile_strong_execution(state.base, state.delta)
    assert transition.output_plan == transition.execution_bundle.output_plan
    with pytest.raises(ValueError, match="present exactly for a query-bearing transition"):
        replace(transition, facts=replace(transition.facts, query_count=0))


def test_strong_transition_has_one_bundle_owned_output_plan_truth_source() -> None:
    assert "output_plan" not in {field.name for field in fields(StrongTransition)}


def test_base_updates_and_reserved_reuse_precede_strong_overflow_with_exact_facts() -> None:
    state = initialize_strong_strategy(
        {(0, 0): 1, (0, 1): 2, (1, 0): 3},
        rows=2,
        cols=8,
        effective_slots=4,
        partition_rows=2,
        matrix_value_bound=9,
        max_row_nnz=8,
        reserved_slack_beta=0.5,
        segment_width=2,
    )

    transition = advance_strong_publication(
        state,
        _window(
            NetUpdate(0, 0, 1, -4),
            NetUpdate(1, 0, 3, 0),
            NetUpdate(0, 2, 0, 5),
            NetUpdate(0, 3, 0, 6),
        ),
    )

    assert transition.state.base.coord_to_slot.keys() == {(0, 0), (0, 1), (0, 2)}
    assert decode_strong_state(transition.state) == {
        (0, 0): -4,
        (0, 1): 2,
        (0, 2): 5,
        (0, 3): 6,
    }
    assert transition.state.version_id == "v00000001"
    assert transition.facts.value_patch_chunks == 2
    assert transition.facts.ci_patch_entries == 1
    assert transition.facts.ci_full_sync_entries == 4
    assert transition.facts.metadata_units == 5
    assert transition.facts.rebuilt_ciphertexts == 0
    assert transition.facts.delta_ciphertexts == 1
    assert transition.facts.delta_rebuilt_ciphertexts == 1
    assert transition.facts.absorbed_reserved == 1
    assert transition.facts.absorbed_natural_padding == 0
    assert transition.facts.absorbed_tombstone == 0
    assert transition.facts.overflow == 1
    assert transition.facts.overflow_rows == (0,)
    assert transition.facts.active_component_ids == (
        "base",
        "strong-packed-coo-delta",
    )
    assert transition.output_plan == transition.execution_bundle.output_plan


def test_multiple_new_segments_on_one_page_rebuild_one_page_and_full_sync_once() -> None:
    state = initialize_strong_strategy(
        {(0, 0): 1, (0, 1): 2},
        rows=1,
        cols=8,
        effective_slots=4,
        partition_rows=1,
        matrix_value_bound=9,
        max_row_nnz=8,
        segment_width=2,
    )

    transition = advance_strong_publication(
        state,
        _window(
            NetUpdate(0, 2, 0, 3),
            NetUpdate(0, 3, 0, 4),
            NetUpdate(0, 4, 0, 5),
            NetUpdate(0, 5, 0, 6),
        ),
    )

    assert len(transition.state.delta.segments) == 2
    assert transition.facts.overflow == 4
    assert transition.facts.delta_ciphertexts == 1
    assert transition.facts.delta_rebuilt_ciphertexts == 1
    assert transition.facts.ci_patch_entries == 0
    assert transition.facts.ci_full_sync_entries == 4
    assert transition.facts.metadata_units == 4

    new_page = advance_strong_publication(
        transition.state,
        _window(NetUpdate(0, 6, 0, 7), index=1),
    )

    assert len(new_page.state.delta.segments) == 3
    assert new_page.facts.overflow == 1
    assert new_page.facts.delta_ciphertexts == 2
    assert new_page.facts.delta_rebuilt_ciphertexts == 1
    assert new_page.facts.ci_patch_entries == 0
    assert new_page.facts.ci_full_sync_entries == 4


def test_strong_tombstone_revival_has_no_ci_patch_but_other_same_row_hole_has_one() -> None:
    initial = initialize_strong_strategy(
        {(0, 0): 1, (0, 1): 2},
        rows=1,
        cols=8,
        effective_slots=4,
        partition_rows=1,
        matrix_value_bound=9,
        max_row_nnz=8,
        segment_width=2,
    )
    inserted = advance_strong_publication(
        initial,
        _window(NetUpdate(0, 4, 0, 5), NetUpdate(0, 5, 0, 6)),
    )
    modified = advance_strong_publication(
        inserted.state,
        _window(NetUpdate(0, 4, 5, -5), index=1),
    )
    assert modified.facts.overflow == 0
    assert modified.facts.ci_patch_entries == 0
    assert modified.facts.delta_rebuilt_ciphertexts == 1
    assert decode_strong_state(modified.state)[(0, 4)] == -5

    deleted = advance_strong_publication(
        modified.state,
        _window(
            NetUpdate(0, 4, -5, 0),
            NetUpdate(0, 5, 6, 0),
            index=2,
        ),
    )

    assert deleted.facts.ci_patch_entries == 0
    assert deleted.facts.delta_ciphertexts == 1
    assert deleted.facts.delta_rebuilt_ciphertexts == 1
    assert deleted.facts.active_component_ids == (
        "base",
        "strong-packed-coo-delta",
    )
    assert len(deleted.state.delta.segments) == 1
    assert decode_strong_state(deleted.state) == initial.logical
    assert any(
        share.component_id == "strong-packed-coo-delta"
        for share in deleted.output_plan.shares
    )

    query_only = advance_strong_publication(
        deleted.state,
        _window(index=3, queries=4),
    )
    assert query_only.state is deleted.state
    assert query_only.state.version_id == deleted.state.version_id
    assert query_only.facts.delta_ciphertexts == 1
    assert query_only.facts.active_component_ids == (
        "base",
        "strong-packed-coo-delta",
    )
    assert query_only.output_plan == compile_strong_execution(
        deleted.state.base,
        deleted.state.delta,
    ).output_plan

    exact = advance_strong_publication(
        deleted.state,
        _window(NetUpdate(0, 5, 0, 7), index=4),
    )
    assert exact.facts.overflow == 1
    assert exact.facts.ci_patch_entries == 0
    assert exact.state.delta.segments[0].entries[1].value == 7

    deleted_again = advance_strong_publication(
        exact.state,
        _window(NetUpdate(0, 5, 7, 0), index=5),
    )
    other_hole = advance_strong_publication(
        deleted_again.state,
        _window(NetUpdate(0, 6, 0, 8), index=6),
    )
    assert other_hole.facts.overflow == 1
    assert other_hole.facts.ci_patch_entries == 1
    assert len(other_hole.state.delta.segments) == 1


def test_base_natural_padding_is_reused_before_allocating_strong_delta() -> None:
    state = initialize_strong_strategy(
        {(0, 0): 1, (0, 1): 2, (0, 2): 3, (1, 0): 4},
        rows=2,
        cols=8,
        effective_slots=4,
        partition_rows=2,
        matrix_value_bound=9,
        max_row_nnz=8,
        segment_width=2,
    )

    transition = advance_strong_publication(
        state,
        _window(NetUpdate(1, 1, 0, 5)),
    )

    assert transition.facts.absorbed_natural_padding == 1
    assert transition.facts.absorbed_reserved == 0
    assert transition.facts.absorbed_tombstone == 0
    assert transition.facts.overflow == 0
    assert transition.facts.ci_patch_entries == 1
    assert transition.facts.delta_ciphertexts == 0
    assert transition.state.delta.segments == ()
    assert (1, 1) in transition.state.base.coord_to_slot
    assert decode_strong_state(transition.state) == {**state.logical, (1, 1): 5}


def test_base_exact_tombstone_revival_retains_ci_without_a_patch() -> None:
    initial = initialize_strong_strategy(
        {(0, 0): 1, (0, 1): 2},
        rows=1,
        cols=5,
        effective_slots=4,
        partition_rows=1,
        matrix_value_bound=9,
        max_row_nnz=5,
        segment_width=2,
    )
    deleted = advance_strong_publication(
        initial,
        _window(NetUpdate(0, 0, 1, 0), NetUpdate(0, 1, 2, 0)),
    )

    revived = advance_strong_publication(
        deleted.state,
        _window(NetUpdate(0, 1, 0, 3), index=1),
    )

    assert revived.facts.absorbed_tombstone == 1
    assert revived.facts.ci_patch_entries == 0
    assert revived.facts.overflow == 0
    assert revived.state.delta.segments == ()
    assert decode_strong_state(revived.state) == {(0, 1): 3}


def test_base_different_column_tombstone_reuse_patches_ci_once() -> None:
    initial = initialize_strong_strategy(
        {(0, 0): 1, (0, 1): 2},
        rows=1,
        cols=5,
        effective_slots=4,
        partition_rows=1,
        matrix_value_bound=9,
        max_row_nnz=5,
        segment_width=2,
    )
    deleted = advance_strong_publication(
        initial,
        _window(NetUpdate(0, 0, 1, 0)),
    )

    reused = advance_strong_publication(
        deleted.state,
        _window(NetUpdate(0, 2, 0, 3), index=1),
    )

    assert reused.facts.absorbed_tombstone == 1
    assert reused.facts.ci_patch_entries == 1
    assert reused.facts.overflow == 0
    assert reused.state.delta.segments == ()
    assert decode_strong_state(reused.state) == {(0, 1): 2, (0, 2): 3}


def test_strong_holes_are_never_reused_across_rows() -> None:
    initial = initialize_strong_strategy(
        {(0, 0): 1, (1, 0): 2},
        rows=2,
        cols=5,
        effective_slots=4,
        partition_rows=2,
        matrix_value_bound=9,
        max_row_nnz=5,
        segment_width=2,
    )
    row_zero = advance_strong_publication(
        initial,
        _window(NetUpdate(0, 1, 0, 3)),
    )

    row_one = advance_strong_publication(
        row_zero.state,
        _window(NetUpdate(1, 1, 0, 4), index=1),
    )

    assert [segment.owner_row for segment in row_one.state.delta.segments] == [0, 1]
    assert row_one.state.delta.segments[0].entries[1] is None
    assert row_one.facts.overflow == 1
    assert row_one.facts.delta_ciphertexts == 1
    assert row_one.facts.delta_rebuilt_ciphertexts == 1
    assert row_one.facts.ci_patch_entries == 1
    assert row_one.facts.ci_full_sync_entries == 0


@pytest.mark.parametrize("segment_width", (1, 3, 9, True))
def test_strong_segment_width_must_be_a_fitting_power_of_two(
    segment_width: int,
) -> None:
    assert "segment_width" in {field.name for field in fields(StrongStrategyConfig)}
    assert "c" not in {field.name for field in fields(StrongStrategyConfig)}
    with pytest.raises(ValueError, match="power of two"):
        initialize_strong_strategy(
            {(0, 0): 1},
            rows=1,
            cols=4,
            effective_slots=8,
            segment_width=segment_width,
        )

    assert initialize_strong_strategy(
        {(0, 0): 1},
        rows=1,
        cols=4,
        effective_slots=8,
        segment_width=2,
    ).config.segment_width == 2
    assert initialize_strong_strategy(
        {(0, 0): 1},
        rows=1,
        cols=4,
        effective_slots=8,
        segment_width=8,
    ).config.segment_width == 8


@pytest.mark.parametrize(
    ("window", "message"),
    (
        (replace(_window(), index=True), "window.index"),
        (replace(_window(), start_time=float("nan")), "times"),
        (replace(_window(), start_time=2.0, end_time=1.0), "times"),
        (replace(_window(), updates=[]), "updates must be a tuple"),
        (replace(_window(), query_count=True), "query_count"),
        (replace(_window(), reason=""), "reason"),
        (replace(_window(), updates=(object(),)), "NetUpdate"),
        (_window(NetUpdate(True, 0, 1, 2)), "strict integers"),
        (_window(NetUpdate(0, 0, 1, True)), "strict integers"),
        (_window(NetUpdate(0, 0, 1, 1)), "no-op"),
        (_window(NetUpdate(0, 4, 0, 1)), "outside"),
        (_window(NetUpdate(0, 0, 99, 2)), "before"),
        (_window(NetUpdate(0, 0, 1, 8)), "value bound"),
        (
            _window(NetUpdate(0, 0, 1, 2), NetUpdate(0, 0, 1, 3)),
            "unique coordinates",
        ),
        (
            _window(NetUpdate(0, 1, 0, 2), NetUpdate(0, 2, 0, 3)),
            "row nonzero bound",
        ),
    ),
)
def test_malformed_strong_windows_fail_atomically(
    window: PublicationWindow, message: str
) -> None:
    state = initialize_strong_strategy(
        {(0, 0): 1},
        rows=1,
        cols=4,
        effective_slots=4,
        matrix_value_bound=7,
        max_row_nnz=2,
        segment_width=2,
    )
    snapshot = copy.deepcopy(state)

    with pytest.raises(ValueError, match=message):
        advance_strong_publication(state, window)

    assert state == snapshot
    assert decode_strong_state(state) == {(0, 0): 1}


def test_version_inconsistent_strong_snapshot_fails_atomically() -> None:
    state = initialize_strong_strategy(
        {(0, 0): 1},
        rows=1,
        cols=4,
        effective_slots=4,
        segment_width=2,
    )
    inconsistent = replace(state, version_id="v00000001")

    with pytest.raises(AssertionError, match="version identifier"):
        advance_strong_publication(inconsistent, _window())

    assert decode_strong_state(state) == {(0, 0): 1}


@pytest.mark.parametrize(
    "order",
    (
        ("strategy_state", "query_compiler", "strong_execution"),
        ("query_compiler", "strong_execution", "strategy_state"),
        ("strong_execution", "strategy_state", "query_compiler"),
    ),
)
def test_strategy_and_compiler_modules_import_in_any_order(order: tuple[str, ...]) -> None:
    source_root = Path(__file__).parents[1] / "src"
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(source_root)
    command = ";".join(f"import dynamic_cssc.{module}" for module in order)

    completed = subprocess.run(
        [sys.executable, "-c", command],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr


def test_importing_strategy_state_does_not_eagerly_import_the_compiler() -> None:
    source_root = Path(__file__).parents[1] / "src"
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(source_root)
    command = (
        "import sys; import dynamic_cssc.strategy_state; "
        "assert 'dynamic_cssc.strong_execution' not in sys.modules"
    )

    completed = subprocess.run(
        [sys.executable, "-c", command],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr
