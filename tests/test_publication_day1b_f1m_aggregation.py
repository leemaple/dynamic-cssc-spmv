from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from fractions import Fraction

import pytest

from dynamic_cssc.day2_calibration_authority import PRIMITIVE_NAMES
from dynamic_cssc.publication_day1b_accounting import (
    PUBLICATION_DAY1B_ACCOUNTING_DOMAIN,
    Day1BPhaseAccounting,
    Day1BQueryWindowAccounting,
    PublicationDay1BAccounting,
)
from dynamic_cssc.publication_day1b_f1m_aggregation import (
    DAY1B_F1M_MAX_CHARGED_SIZE_CLASS_RECEIPTS_PER_CELL,
    Day1BF1MAggregationError,
    Day1BF1MCompletePhaseAudit,
    Day1BF1MCompleteScheduleAudit,
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


def _accounting(
    windows: tuple[Day1BQueryWindowAccounting, ...],
    *,
    retained_phases: tuple[str, ...] = ("tuning-prefix", "held-out"),
) -> PublicationDay1BAccounting:
    phases = ("warmup", "tuning-prefix", "held-out")
    boundaries = ((0, 10), (10, 40), (40, 100))
    phase_rows: list[Day1BPhaseAccounting] = []
    for phase, (start, end) in zip(phases, boundaries, strict=True):
        selected = tuple(window for window in windows if window.phase == phase)
        phase_rows.append(
            Day1BPhaseAccounting(
                phase=phase,  # type: ignore[arg-type]
                accepted_group_start=start,
                accepted_group_end=end,
                realized_window_count=len(selected) + 1,
                realized_set_count=sum(window.set_count for window in selected),
                realized_net_update_count=sum(
                    window.net_update_count for window in selected
                ),
                realized_query_count=sum(window.query_count for window in selected),
                query_window_count=len(selected),
                query_window_stream_sha256=_digest(
                    {"phase": phase, "windows": [row.to_document() for row in selected]}
                ),
                strategy_metrics_sha256=_digest({"phase": phase, "metrics": "fixture"}),
                update_primitive_counts=(0,) * len(PRIMITIVE_NAMES),
                query_primitive_counts=(0,) * len(PRIMITIVE_NAMES),
            )
        )
    candidate_id = "reference-a" if len(retained_phases) == 2 else "ablation-a"
    return PublicationDay1BAccounting(
        candidate_id=candidate_id,
        candidate_policy_sha256="e" * 64,
        domain=PUBLICATION_DAY1B_ACCOUNTING_DOMAIN,
        phases=tuple(phase_rows),
        window_stream_sha256="1" * 64,
        query_window_stream_sha256=_query_stream_sha256(windows),
        realized_window_count=sum(phase.realized_window_count for phase in phase_rows),
        realized_query_window_count=len(windows),
        realized_query_count=sum(window.query_count for window in windows),
        terminal_version_id="v00000001",
        terminal_logical_state_sha256="4" * 64,
    )


def _complete_schedule_audit(
    accounting: PublicationDay1BAccounting,
) -> Day1BF1MCompleteScheduleAudit:
    return Day1BF1MCompleteScheduleAudit(
        tuple(
            Day1BF1MCompletePhaseAudit(
                phase=phase.phase,
                accepted_group_start=phase.accepted_group_start,
                accepted_group_end=phase.accepted_group_end,
                realized_window_count=phase.realized_window_count,
                realized_set_count=phase.realized_set_count,
                realized_query_count=phase.realized_query_count,
                consumed_window_audit_stream_sha256=_digest(
                    {"phase": phase.phase, "audit": "fixture"}
                ),
            )
            for phase in accounting.phases
        )
    )


def _context(
    windows: tuple[Day1BQueryWindowAccounting, ...],
    *,
    retained_phases: tuple[str, ...] = ("tuning-prefix", "held-out"),
) -> Day1BF1MControllerContext:
    accounting = _accounting(windows, retained_phases=retained_phases)
    audit = _complete_schedule_audit(accounting)
    phase_query_counts = tuple(phase.realized_query_count for phase in accounting.phases)
    phase_window_counts = tuple(phase.realized_window_count for phase in accounting.phases)
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
        trace_manifest_sha256="a" * 64,
        candidate_catalog_sha256="b" * 64,
        resource_policy_sha256="c" * 64,
        worker_build_identity_sha256="d" * 64,
        worker_runtime_identity_sha256="e" * 64,
        dataset_id="stack-overflow",
        dataset_release="test-release",
        semantics="T2",
        source_partition=0,
        unit_identity_sha256="f" * 64,
        cell_binding_sha256="1" * 64,
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
        complete_window_count=accounting.realized_window_count,
        query_window_count=len(windows),
        zero_query_window_count=(
            accounting.realized_window_count - accounting.realized_query_window_count
        ),
        total_query_count=sum(phase_query_counts),
        phase_window_counts=phase_window_counts,  # type: ignore[arg-type]
        phase_query_counts=phase_query_counts,  # type: ignore[arg-type]
        complete_window_stream_sha256=accounting.window_stream_sha256,
        complete_phase_audit_root_sha256=(audit.complete_phase_audit_root_sha256),
        accounting_sha256=accounting.accounting_sha256,
        query_window_stream_sha256=accounting.query_window_stream_sha256,
    )


def _summary(
    windows: tuple[Day1BQueryWindowAccounting, ...],
    *,
    f1m_policy: str = "uniform-random-or-zero",
    size_authority: Day1BSerializedObjectSizeAuthority | None = None,
    serialized_payload_bytes_per_cell_maximum: int = 1_000_000,
) -> object:
    controller = Day1BF1MController(
        accepted_group_count=100,
        retained_phases=("tuning-prefix", "held-out"),
        f1m_policy=f1m_policy,
        size_authority=size_authority or _authority(),
        serialized_object_bytes_maximum=10_000,
        serialized_payload_bytes_per_cell_maximum=(
            serialized_payload_bytes_per_cell_maximum
        ),
    )
    for window in windows:
        controller.accept_query_window(window)
    accounting = _accounting(windows)
    return controller.finish(
        context=_context(windows),
        accounting=accounting,
        complete_schedule_audit=_complete_schedule_audit(accounting),
    )


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
    assert summary.serialized_object_bytes_maximum == 10_000
    assert summary.serialized_payload_bytes_per_cell_maximum == 1_000_000
    assert summary.to_document()["serialized_object_bytes_maximum"] == 10_000
    assert (
        summary.to_document()["serialized_payload_bytes_per_cell_maximum"]
        == 1_000_000
    )


@pytest.mark.parametrize(
    "field",
    (
        "trace_manifest_sha256",
        "candidate_catalog_sha256",
        "resource_policy_sha256",
    ),
)
def test_context_root_binds_trace_catalog_and_resource_policy(field: str) -> None:
    original = _context(())
    changed = replace(original, **{field: "f" * 64})

    assert original.context_sha256 != changed.context_sha256


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


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("result_id", "different-result-id"),
        ("result_ordinal", 1),
    ),
)
def test_result_identity_and_ordinal_are_bound_into_route_coverage(
    field: str,
    value: object,
) -> None:
    original = _window(
        phase="held-out",
        index=20,
        accepted_start=40,
        accepted_end=60,
        first_query=0,
        query_count=3,
        random_routes=1,
        dummy_routes=0,
        identity="route-result",
    )
    changed_route = replace(
        original.query_plan.f1m_routes[0],
        **{field: value},
    )
    changed_plan = replace(
        original.query_plan,
        returned_share_count=(2 if field == "result_ordinal" else 1),
        f1m_routes=(changed_route,),
    )
    changed = replace(original, query_plan=changed_plan)

    policy = "overlap-only" if field == "result_ordinal" else "uniform-random-or-zero"
    assert _summary((original,), f1m_policy=policy).route_coverage_sha256 != (
        _summary((changed,), f1m_policy=policy).route_coverage_sha256
    )


def test_day2_archive_and_size_profile_identity_are_bound_into_route_coverage() -> None:
    window = _window(
        phase="held-out",
        index=20,
        accepted_start=40,
        accepted_end=60,
        first_query=0,
        query_count=3,
        random_routes=1,
        dummy_routes=0,
        identity="day2-lineage",
    )
    original = _summary((window,), size_authority=_authority())
    substituted_authority = replace(
        _authority(),
        day2_outer_archive_sha256="a" * 64,
        serialized_object_size_profile_sha256="b" * 64,
    )
    substituted = _summary((window,), size_authority=substituted_authority)

    assert original.logical_charged_byte_count == substituted.logical_charged_byte_count
    assert original.route_coverage_sha256 != substituted.route_coverage_sha256


def test_uniform_policy_requires_a_kind_for_every_returned_share() -> None:
    window = _window(
        phase="held-out",
        index=20,
        accepted_start=40,
        accepted_end=60,
        first_query=0,
        query_count=1,
        random_routes=1,
        dummy_routes=0,
        identity="missing-kind",
    )
    window = replace(
        window,
        query_plan=replace(window.query_plan, returned_share_count=2),
    )
    controller = Day1BF1MController(
        accepted_group_count=100,
        retained_phases=("tuning-prefix", "held-out"),
        f1m_policy="uniform-random-or-zero",
        size_authority=_authority(),
        serialized_object_bytes_maximum=10_000,
        serialized_payload_bytes_per_cell_maximum=1_000_000,
    )

    with pytest.raises(Day1BF1MAggregationError, match="classify every returned share"):
        controller.accept_query_window(window)


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
        serialized_object_bytes_maximum=10_000,
        serialized_payload_bytes_per_cell_maximum=1_000_000,
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
        serialized_object_bytes_maximum=10_000,
        serialized_payload_bytes_per_cell_maximum=1_000_000,
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
        serialized_object_bytes_maximum=10_000,
        serialized_payload_bytes_per_cell_maximum=1_000_000,
    )
    controller.accept_query_window(window)
    accounting = _accounting((window,), retained_phases=("held-out",))

    with pytest.raises(Day1BF1MAggregationError, match="do not reconcile"):
        controller.finish(
            context=replace(
                _context((window,), retained_phases=("held-out",)),
                query_window_stream_sha256="f" * 64,
            ),
            accounting=accounting,
            complete_schedule_audit=_complete_schedule_audit(accounting),
        )


@pytest.mark.parametrize(
    "tamper",
    (
        "inflated-zero-window-count",
        "accounting-root",
        "complete-window-root",
        "complete-phase-audit-root",
        "phase-audit-set-count",
    ),
)
def test_finish_recomputes_every_accounting_and_full_window_context_root(
    tamper: str,
) -> None:
    window = _window(
        phase="held-out",
        index=20,
        accepted_start=40,
        accepted_end=60,
        first_query=0,
        query_count=3,
        random_routes=1,
        dummy_routes=0,
        identity=f"context-{tamper}",
    )
    accounting = _accounting((window,), retained_phases=("held-out",))
    audit = _complete_schedule_audit(accounting)
    context = _context((window,), retained_phases=("held-out",))
    if tamper == "inflated-zero-window-count":
        context = replace(
            context,
            complete_window_count=context.complete_window_count + 1,
            zero_query_window_count=context.zero_query_window_count + 1,
            phase_window_counts=(
                context.phase_window_counts[0] + 1,
                *context.phase_window_counts[1:],
            ),
        )
    elif tamper == "accounting-root":
        context = replace(context, accounting_sha256="f" * 64)
    elif tamper == "complete-window-root":
        context = replace(context, complete_window_stream_sha256="f" * 64)
    elif tamper == "complete-phase-audit-root":
        context = replace(context, complete_phase_audit_root_sha256="f" * 64)
    else:
        last = replace(
            audit.phase_audits[-1],
            realized_set_count=audit.phase_audits[-1].realized_set_count + 1,
        )
        audit = Day1BF1MCompleteScheduleAudit((*audit.phase_audits[:-1], last))
    controller = Day1BF1MController(
        accepted_group_count=100,
        retained_phases=("held-out",),
        f1m_policy="overlap-only",
        size_authority=_authority(),
        serialized_object_bytes_maximum=10_000,
        serialized_payload_bytes_per_cell_maximum=1_000_000,
    )
    controller.accept_query_window(window)

    with pytest.raises(Day1BF1MAggregationError, match="do not reconcile"):
        controller.finish(
            context=context,
            accounting=accounting,
            complete_schedule_audit=audit,
        )


def test_size_and_per_cell_payload_caps_are_enforced_before_evidence() -> None:
    with pytest.raises(Day1BF1MAggregationError, match="object-byte cap"):
        Day1BF1MController(
            accepted_group_count=100,
            retained_phases=("held-out",),
            f1m_policy="overlap-only",
            size_authority=_authority(),
            serialized_object_bytes_maximum=1_099,
            serialized_payload_bytes_per_cell_maximum=1_000_000,
        )

    with pytest.raises(Day1BF1MAggregationError, match="object-byte cap"):
        Day1BF1MController(
            accepted_group_count=100,
            retained_phases=("held-out",),
            f1m_policy="overlap-only",
            size_authority=replace(_authority(), ciphertext_bytes=1_300),
            serialized_object_bytes_maximum=1_250,
            serialized_payload_bytes_per_cell_maximum=1_000_000,
        )

    window = _window(
        phase="held-out",
        index=20,
        accepted_start=40,
        accepted_end=60,
        first_query=0,
        query_count=3,
        random_routes=1,
        dummy_routes=0,
        identity="payload-cap",
    )
    with pytest.raises(Day1BF1MAggregationError, match="payload cap"):
        _summary(
            (window,),
            serialized_payload_bytes_per_cell_maximum=3_299,
        )


def test_each_charged_f1m_document_fits_the_inclusive_jsonl_bound() -> None:
    window = _window(
        phase="held-out",
        index=20,
        accepted_start=40,
        accepted_end=60,
        first_query=0,
        query_count=3,
        random_routes=1,
        dummy_routes=1,
        identity="jsonl-bound",
    )
    summary = _summary((window,))

    assert all(
        len(_canonical(item.to_document())) <= 2_048
        for item in summary.charged_size_classes
    )
    assert {
        item.serialized_size_profile_key for item in summary.charged_size_classes
    } == {
        "f1m_random_zero_sum_ciphertext_bytes",
        "f1m_encrypted_zero_dummy_ciphertext_bytes",
    }


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
