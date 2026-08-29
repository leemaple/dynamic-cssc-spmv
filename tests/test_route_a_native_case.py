from __future__ import annotations

import json
from pathlib import Path

import pytest

import dynamic_cssc.route_a_native_case as native_case_module
from dynamic_cssc.route_a_native_case import (
    RouteANativeCaseError,
    compile_route_a_terminal_native_case,
)
from dynamic_cssc.route_a_strategy import ROUTE_A_STRATEGY_CANDIDATES
from dynamic_cssc.route_a_workloads import generate_route_a_formal_trace

ROOT = Path(__file__).resolve().parents[1]
MACHINE_PLAN_BYTES = (ROOT / "config/route-a-publication-plan.json").read_bytes()
SHARD_ID = "1" * 64


@pytest.mark.parametrize("strategy_candidate_id", ROUTE_A_STRATEGY_CANDIDATES)
def test_terminal_native_case_closes_the_exact_s_case(
    strategy_candidate_id: str,
) -> None:
    trace = generate_route_a_formal_trace(scale="S", formal_seed=20260822)

    case = compile_route_a_terminal_native_case(
        trace,
        strategy_candidate_id=strategy_candidate_id,
        shard_identity_sha256=SHARD_ID,
        unit_attempt_ordinal=0,
        machine_plan_bytes=MACHINE_PLAN_BYTES,
    )

    assert case.execution_kind == (
        "strong"
        if strategy_candidate_id == "packed-coo-cloud-segmented-delta/segment-width=128"
        else "ordinary"
    )
    assert case.terminal_window_ordinal == 511
    assert case.terminal_global_query_ordinal == 511
    assert case.terminal_version_id == "v00000512"
    assert len(case.direct_oracle_output) == 256
    assert case.query_vector.suite_role == "formal"
    assert tuple(name for name, _content in case.retained_canonical_inputs) == (
        "cloud-visible-plan.json",
        "machine-plan.json",
        "output-plan.json",
        "private-plan.json",
        "query-vector-domain.json",
        "query-vector.json",
        "synthetic-event-trace.json",
        "synthetic-initial-state.json",
        "window-trace-rho1.json",
    )
    binding = json.loads(case.case_binding_bytes)
    assert binding["authority"] == {
        "formal_artifact": False,
        "publication_authority": False,
    }
    assert binding["identity"]["terminal_global_query_ordinal"] == 511
    assert binding["bindings"]["retained_canonical_input_root"] == (
        case.retained_canonical_input_root
    )


def test_strong_s_terminal_case_exercises_its_required_auxiliary_path() -> None:
    case = compile_route_a_terminal_native_case(
        generate_route_a_formal_trace(scale="S", formal_seed=20260822),
        strategy_candidate_id=("packed-coo-cloud-segmented-delta/segment-width=128"),
        shard_identity_sha256=SHARD_ID,
        unit_attempt_ordinal=0,
        machine_plan_bytes=MACHINE_PLAN_BYTES,
    )

    coverage = dict(case.mechanism_coverage)
    assert coverage["nonempty_auxiliary_segment"] is True
    structural = json.loads(case.structural_vector_bytes)
    assert structural["topology"]["auxiliary_segment_count"] > 0
    assert structural["ordered_operation_types"]
    assert structural["rotation_key_indices"]


def test_terminal_case_omits_all_earlier_query_plan_assembly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_only_calls = 0
    terminal_calls = 0
    real_state_only = native_case_module.advance_route_a_candidate_state_only
    real_terminal = native_case_module.advance_route_a_candidate_timed

    def observed_state_only(*args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        nonlocal state_only_calls
        state_only_calls += 1
        return real_state_only(*args, **kwargs)  # type: ignore[arg-type]

    def observed_terminal(*args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        nonlocal terminal_calls
        terminal_calls += 1
        return real_terminal(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        native_case_module,
        "advance_route_a_candidate_state_only",
        observed_state_only,
    )
    monkeypatch.setattr(
        native_case_module,
        "advance_route_a_candidate_timed",
        observed_terminal,
    )

    compile_route_a_terminal_native_case(
        generate_route_a_formal_trace(scale="S", formal_seed=20260822),
        strategy_candidate_id="periodic-repack/windows=1",
        shard_identity_sha256=SHARD_ID,
        unit_attempt_ordinal=0,
        machine_plan_bytes=MACHINE_PLAN_BYTES,
    )

    assert state_only_calls == 511
    assert terminal_calls == 1


def test_terminal_native_case_rejects_a_changed_machine_plan() -> None:
    trace = generate_route_a_formal_trace(scale="S", formal_seed=20260822)

    with pytest.raises(RouteANativeCaseError, match="machine-plan"):
        compile_route_a_terminal_native_case(
            trace,
            strategy_candidate_id="periodic-repack/windows=1",
            shard_identity_sha256=SHARD_ID,
            unit_attempt_ordinal=0,
            machine_plan_bytes=MACHINE_PLAN_BYTES + b" ",
        )
