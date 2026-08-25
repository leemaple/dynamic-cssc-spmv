from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from fractions import Fraction

import pytest

from dynamic_cssc.publication_day1b_accounting import Day1BQueryWindowAccounting
from dynamic_cssc.publication_day1b_f1m_aggregation import (
    DAY1B_F1M_MAX_CHARGED_SIZE_CLASS_RECEIPTS_PER_CELL,
    Day1BF1MAggregationError,
    Day1BF1MController,
    Day1BF1MControllerContext,
    Day1BF1MPhaseBoundary,
    Day1BSerializedObjectSizeAuthority,
)
from dynamic_cssc.simulator import F1MRouteAccounting, QueryPlanAccounting


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _authority() -> Day1BSerializedObjectSizeAuthority:
    return Day1BSerializedObjectSizeAuthority(
        source_git_sha="1" * 40,
        day2_experiment_source_git_sha="2" * 40,
        day2_outer_archive_sha256="3" * 64,
        serialized_object_size_profile_sha256="4" * 64,
        ciphertext_bytes=1000,
        f1m_random_zero_sum_ciphertext_bytes=1100,
        f1m_encrypted_zero_dummy_ciphertext_bytes=1200,
        serialized_rotation_key_inventory_bytes=2000,
        serialized_eval_mult_key_bytes=3000,
    )


def _window(
    *,
    phase: str,
    index: int,
    accepted_start: int,
    accepted_end: int,
    first_query: int,
    query_count: int,
    random_routes: int,
    dummy_routes: int,
    identity: str,
) -> Day1BQueryWindowAccounting:
    routes = tuple(
        F1MRouteAccounting(
            result_id=f"random-result-{identity}-{ordinal}",
            result_ordinal=ordinal,
            f1m_route_ordinal=ordinal,
            component_id=f"random-component-{identity}-{ordinal}",
            output_block_id=f"random-block-{identity}-{ordinal}",
            kind="random-zero-sum",
        )
        for ordinal in range(random_routes)
    ) + tuple(
        F1MRouteAccounting(
            result_id=f"dummy-result-{identity}-{ordinal}",
            result_ordinal=random_routes + ordinal,
            f1m_route_ordinal=random_routes + ordinal,
            component_id=f"dummy-component-{identity}-{ordinal}",
            output_block_id=f"dummy-block-{identity}-{ordinal}",
            kind="encrypted-zero-dummy",
        )
        for ordinal in range(dummy_routes)
    )
    return Day1BQueryWindowAccounting(
        phase=phase,  # type: ignore[arg-type]
        window_index=index,
        accepted_group_start=accepted_start,
        accepted_group_end=accepted_end,
        start_time=Fraction(index, 10),
        end_time=Fraction(index + 1, 10),
        set_count=1,
        net_update_count=1,
        first_global_query_ordinal=first_query,
        query_count=query_count,
        rotations_per_query=((-1, 1), (1, 2)),
        query_plan=QueryPlanAccounting(
            version_id=f"version-{identity}",
            cloud_program_digest=hashlib.sha256(f"cloud:{identity}".encode()).hexdigest(),
            output_plan_digest=hashlib.sha256(f"output:{identity}".encode()).hexdigest(),
            execution_binding_digest=hashlib.sha256(
                f"execution:{identity}".encode()
            ).hexdigest(),
            private_plan_digest=hashlib.sha256(f"private:{identity}".encode()).hexdigest(),
            returned_share_count=len(routes),
            f1m_routes=routes,
        ),
    )


def _query_stream_sha256(windows: tuple[Day1BQueryWindowAccounting, ...]) -> str:
    stream = hashlib.sha256()
    for window in windows:
        stream.update(_canonical(window.to_document()))
    return _digest(
        {
            "element_count": len(windows),
            "element_stream_sha256": stream.hexdigest(),
            "schema_version": "dynamic-cssc-publication-day1b-query-window-stream-v1",
        }
    )


def _context(
    windows: tuple[Day1BQueryWindowAccounting, ...],
    *,
    retained_phases: tuple[str, ...] = ("tuning-prefix", "held-out"),
) -> Day1BF1MControllerContext:
    phases = ("warmup", "tuning-prefix", "held-out")
    phase_query_window_counts = tuple(
        sum(window.phase == phase for window in windows) for phase in phases
    )
    phase_query_counts = tuple(
        sum(window.query_count for window in windows if window.phase == phase)
        for phase in phases
    )
    phase_window_counts = tuple(count + 1 for count in phase_query_window_counts)
    return Day1BF1MControllerContext(
        publication_source_git_sha="1" * 40,
        publication_behavior_set_schema_version=(
            "dynamic-cssc-day1b-preparatory-behavior-set-v11"
        ),
        publication_behavior_inventory_sha256="5" * 64,
        terminal_registration_sha256="6" * 64,
        day1_registration_anchor_sha256="7" * 64,
        trace_post_run_anchor_sha256="8" * 64,
        acquisition_bundle_sha256="9" * 64,
        worker_build_identity_sha256="a" * 64,
        worker_runtime_identity_sha256="b" * 64,
        dataset_id="stack-overflow",
        dataset_release="test-release",
        semantics="T2",
        source_partition=0,
        unit_identity_sha256="c" * 64,
        cell_binding_sha256="d" * 64,
        cell_ordinal=0,
        freshness="0.1",
        rho="1",
        candidate_id=("reference-a" if len(retained_phases) == 2 else "ablation-a"),
        candidate_role=("reference" if len(retained_phases) == 2 else "ablation"),
        candidate_policy_sha256="e" * 64,
        retained_phases=retained_phases,
        phase_boundaries=(
            Day1BF1MPhaseBoundary("warmup", 0, 10),
            Day1BF1MPhaseBoundary("tuning-prefix", 10, 40),
            Day1BF1MPhaseBoundary("held-out", 40, 100),
        ),
        event_schedule_sha256="f" * 64,
        query_vector_sha256="0" * 64,
        accepted_group_count=100,
        complete_window_count=sum(phase_window_counts),
        query_window_count=len(windows),
        zero_query_window_count=3,
        total_query_count=sum(phase_query_counts),
        phase_window_counts=phase_window_counts,  # type: ignore[arg-type]
        phase_query_counts=phase_query_counts,  # type: ignore[arg-type]
        complete_window_stream_sha256="1" * 64,
        complete_phase_audit_root_sha256="2" * 64,
        accounting_sha256="3" * 64,
        query_window_stream_sha256=_query_stream_sha256(windows),
    )


def _summary(
    windows: tuple[Day1BQueryWindowAccounting, ...],
    *,
    f1m_policy: str = "uniform-random-or-zero",
) -> object:
    controller = Day1BF1MController(
        accepted_group_count=100,
        retained_phases=("tuning-prefix", "held-out"),
        f1m_policy=f1m_policy,
        size_authority=_authority(),
    )
    for window in windows:
        controller.accept_query_window(window)
    return controller.finish(context=_context(windows))


def test_cross_window_charging_keeps_route_coverage_but_materializes_four_classes() -> None:
    windows = (
        _window(
            phase="tuning-prefix",
            index=10,
            accepted_start=10,
            accepted_end=20,
            first_query=0,
            query_count=2,
            random_routes=1,
            dummy_routes=1,
            identity="tuning",
        ),
        _window(
            phase="held-out",
            index=20,
            accepted_start=40,
            accepted_end=60,
            first_query=2,
            query_count=3,
            random_routes=2,
            dummy_routes=1,
            identity="heldout",
        ),
    )

    summary = _summary(windows)

    assert summary.phase_query_counts == (0, 2, 3)
    assert summary.phase_random_route_counts == (0, 2, 6)
    assert summary.phase_dummy_route_counts == (0, 2, 3)
    assert len(summary.charged_size_classes) == 4
    assert len(summary.charged_size_classes) <= (
        DAY1B_F1M_MAX_CHARGED_SIZE_CLASS_RECEIPTS_PER_CELL
    )
    assert summary.logical_charged_byte_count == 14_800
    assert {item.ciphertext_bytes for item in summary.charged_size_classes} == {
        1100,
        1200,
    }
    assert {
        item.to_document()["materialized_cryptographic_object_count"]
        for item in summary.charged_size_classes
    } == {0}
    assert not {
        "component_id",
        "output_block_id",
        "output_plan_digest",
        "window_index",
    } & set(summary.charged_size_classes[0].to_document())


def test_route_identity_tamper_changes_coverage_without_changing_charged_totals() -> None:
    original = _window(
        phase="held-out",
        index=20,
        accepted_start=40,
        accepted_end=60,
        first_query=0,
        query_count=3,
        random_routes=1,
        dummy_routes=0,
        identity="original",
    )
    changed_route = replace(
        original.query_plan.f1m_routes[0],
        output_block_id="different-output-block",
    )
    changed = replace(
        original,
        query_plan=replace(original.query_plan, f1m_routes=(changed_route,)),
    )

    original_summary = _summary((original,))
    changed_summary = _summary((changed,))

    assert original_summary.route_coverage_sha256 != changed_summary.route_coverage_sha256
    assert original_summary.logical_charged_byte_count == (
        changed_summary.logical_charged_byte_count
    )


@pytest.mark.parametrize("case", ("query-gap", "accepted-overlap", "phase-regression"))
def test_controller_rejects_noncanonical_route_coverage(case: str) -> None:
    first = _window(
        phase="tuning-prefix",
        index=10,
        accepted_start=10,
        accepted_end=20,
        first_query=0,
        query_count=2,
        random_routes=1,
        dummy_routes=0,
        identity="first",
    )
    second = _window(
        phase="held-out",
        index=20,
        accepted_start=40,
        accepted_end=60,
        first_query=2,
        query_count=3,
        random_routes=1,
        dummy_routes=0,
        identity="second",
    )
    if case == "query-gap":
        second = replace(second, first_global_query_ordinal=3)
    elif case == "accepted-overlap":
        second = replace(second, accepted_group_start=19)
    else:
        second = replace(second, phase="warmup")

    controller = Day1BF1MController(
        accepted_group_count=100,
        retained_phases=("tuning-prefix", "held-out"),
        f1m_policy="uniform-random-or-zero",
        size_authority=_authority(),
    )
    controller.accept_query_window(first)
    with pytest.raises(Day1BF1MAggregationError, match="canonical|contiguous|overlap"):
        controller.accept_query_window(second)


def test_overlap_only_policy_rejects_dummy_route_charges() -> None:
    window = _window(
        phase="held-out",
        index=20,
        accepted_start=40,
        accepted_end=60,
        first_query=0,
        query_count=3,
        random_routes=1,
        dummy_routes=1,
        identity="dummy",
    )
    controller = Day1BF1MController(
        accepted_group_count=100,
        retained_phases=("held-out",),
        f1m_policy="overlap-only",
        size_authority=_authority(),
    )

    with pytest.raises(Day1BF1MAggregationError, match="overlap-only"):
        controller.accept_query_window(window)


def test_finish_rejects_an_omitted_window_or_changed_phase_total() -> None:
    window = _window(
        phase="held-out",
        index=20,
        accepted_start=40,
        accepted_end=60,
        first_query=0,
        query_count=3,
        random_routes=1,
        dummy_routes=0,
        identity="heldout",
    )
    controller = Day1BF1MController(
        accepted_group_count=100,
        retained_phases=("held-out",),
        f1m_policy="overlap-only",
        size_authority=_authority(),
    )
    controller.accept_query_window(window)

    with pytest.raises(Day1BF1MAggregationError, match="exact accounting.*stream"):
        controller.finish(
            context=replace(
                _context((window,), retained_phases=("held-out",)),
                query_window_stream_sha256="f" * 64,
            )
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("ciphertext_bytes", 0),
        ("f1m_random_zero_sum_ciphertext_bytes", 0),
        ("f1m_encrypted_zero_dummy_ciphertext_bytes", 0),
        ("serialized_object_size_profile_sha256", "bad"),
    ),
)
def test_size_authority_rejects_unanchored_or_nonpositive_sizes(
    field: str,
    value: object,
) -> None:
    with pytest.raises(Day1BF1MAggregationError):
        replace(_authority(), **{field: value})
