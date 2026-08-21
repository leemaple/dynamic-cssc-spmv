from __future__ import annotations

import argparse
import json
from fractions import Fraction
from pathlib import Path

import pytest

from dynamic_cssc import simulator as simulator_module
from dynamic_cssc.events import Event, NetUpdate, PublicationWindow
from dynamic_cssc.metrics import StrategyMetrics, UnitCosts
from dynamic_cssc.preflight import PreflightReport
from dynamic_cssc.selection import (
    FixedCandidate,
    build_fixed_candidates,
    parse_experiment_split,
    select_tuned_fixed_candidate,
    split_boundaries,
)
from dynamic_cssc.simulator import (
    SimulationConfig,
    SimulationResult,
    SimulationTarget,
)
from scripts import run_day1_suite
from scripts.run_day1_suite import CausalCellResult, evaluate_causal_cell, run_suite


def _small_experiment_plan() -> dict[str, object]:
    return {
        "plan_version": "0.1.0",
        "split": {"warmup": 0.1, "tuning": 0.3, "held_out": 0.6},
        "synthetic": {
            "rows": 2,
            "cols": 2,
            "initial_nnz_per_row": 1,
            "events": 10,
            "queries_per_update_grid": [1],
            "workloads": ["zipf"],
        },
        "reserved_slack_betas": [0, 0.05, 0.1, 0.2, 0.4],
        "periodic_repack_windows": [1, 4, 16, 64],
        "freshness_seconds": [1.0],
        "bandwidth_profiles_mbps": [100],
    }


@pytest.mark.parametrize("mutation", ["missing", "misspelled", "extra"])
def test_plan_boundary_rejects_noncanonical_synthetic_keys(tmp_path: Path, mutation: str) -> None:
    payload = _small_experiment_plan()
    synthetic = payload["synthetic"]
    assert isinstance(synthetic, dict)
    if mutation == "missing":
        del synthetic["workloads"]
    elif mutation == "misspelled":
        synthetic["rowz"] = synthetic.pop("rows")
    else:
        synthetic["updates"] = synthetic["events"]
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="synthetic keys"):
        run_day1_suite.load_experiment_plan(plan_path)


def test_suite_rejects_cli_dimensions_that_disagree_with_the_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(run_day1_suite, "load_manifest", lambda _path: {})
    monkeypatch.setattr(
        run_day1_suite,
        "run_day1_preflight",
        lambda _manifest: PreflightReport(
            status="pass",
            rows=257,
            cols=521,
            effective_slots=256,
            output_shares=2,
            observed_global_column_index=520,
            modulo_alias_column_index=8,
            global_gather_value=1,
            modulo_alias_value=0,
            reconstructed_matches_direct=True,
            reconstructed_high_row_value=1,
        ),
    )
    monkeypatch.setattr(
        run_day1_suite,
        "load_experiment_plan",
        lambda _path: run_day1_suite.parse_experiment_plan(_small_experiment_plan()),
    )
    monkeypatch.setattr(
        run_day1_suite,
        "generate_initial_matrix",
        lambda *_args, **_kwargs: pytest.fail("generation must not start"),
    )
    args = argparse.Namespace(
        manifest="manifest.json",
        experiment_plan="plan.json",
        output_dir=Path("unused"),
        seed=7,
        rows=3,
        cols=None,
        nnz_per_row=None,
        updates=None,
    )

    with pytest.raises(ValueError, match="--rows.*synthetic.rows"):
        run_suite(args)


def test_split_uses_exact_decimal_fractions_and_keeps_tuning_and_held_out_nonempty() -> None:
    split = parse_experiment_split({"warmup": "0.10", "tuning": "0.30", "held_out": "0.60"})

    assert split == (Fraction(1, 10), Fraction(3, 10), Fraction(3, 5))
    assert split_boundaries(10, split) == (1, 4)


@pytest.mark.parametrize(
    ("values", "message"),
    [
        (
            {"warmup": -0.1, "tuning": 0.5, "held_out": 0.6},
            "nonnegative",
        ),
        (
            {"warmup": 0.1, "tuning": 0.2, "held_out": 0.6},
            "sum to one",
        ),
        (
            {"warmup": False, "tuning": 0.4, "held_out": 0.6},
            "decimal fraction",
        ),
    ],
)
def test_split_rejects_invalid_fractions(values: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        parse_experiment_split(values)


def test_candidate_grid_has_exactly_the_thirteen_fixed_policies() -> None:
    candidates = build_fixed_candidates(
        reserved_slack_betas=[0.0, 0.05, 0.10, 0.20, 0.40],
        periodic_repack_windows=[1, 4, 16, 64],
    )

    assert [candidate.candidate_id for candidate in candidates] == [
        "padding-reuse",
        "mini-cssc-delta",
        "packed-coo-hyb-delta/capacity=128",
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
    ]


@pytest.mark.parametrize(
    ("betas", "periods", "message"),
    [
        (
            [0, 0.05, 0.1, "0.10", 0.4],
            [1, 4, 16, 64],
            "frozen canonical grid",
        ),
        ([0, 0.05, 0.1, 0.2], [1, 4, 16, 64], "exactly five"),
        ([0, 0.05, 0.1, 0.2, 0.4], [1, 4, 16], "exactly four"),
    ],
)
def test_candidate_grid_rejects_duplicates_or_changed_cardinality(
    betas: list[object], periods: list[int], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        build_fixed_candidates(
            reserved_slack_betas=betas,
            periodic_repack_windows=periods,
        )


@pytest.mark.parametrize(
    ("betas", "periods"),
    [
        ([0, 0.05, 0.1, 0.3, 0.4], [1, 4, 16, 64]),
        ([0, 0.05, 0.1, 0.2, 0.4], [1, 4, 8, 64]),
        ([0, 0.05, 0.1, 0.2, 0.4], [1, 4, 16, 16]),
    ],
)
def test_candidate_grid_rejects_any_substitution_from_the_frozen_grid(
    betas: list[object], periods: list[int]
) -> None:
    with pytest.raises(ValueError, match="frozen canonical grid"):
        build_fixed_candidates(
            reserved_slack_betas=betas,
            periodic_repack_windows=periods,
        )


def test_tuning_selector_uses_only_finite_cost_then_canonical_id_for_ties() -> None:
    candidates = (
        FixedCandidate("z-policy", "PaddingReuse-CSSC"),
        FixedCandidate("a-policy", "Mini-CSSC-Delta"),
        FixedCandidate("nonfinite", "Strict-LocalRepack"),
    )
    metrics = {
        "z-policy": StrategyMetrics("PaddingReuse-CSSC", "reference"),
        "a-policy": StrategyMetrics("Mini-CSSC-Delta", "reference"),
        "nonfinite": StrategyMetrics(
            "Strict-LocalRepack", "reference", update_encryptions=float("inf")
        ),
    }

    selected = select_tuned_fixed_candidate(candidates, metrics, UnitCosts())

    assert selected.candidate_id == "a-policy"


def test_cell_batches_all_candidates_and_freezes_between_the_two_replays(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidates = build_fixed_candidates(
        reserved_slack_betas=[0, 0.05, 0.1, 0.2, 0.4],
        periodic_repack_windows=[1, 4, 16, 64],
    )
    windows = [PublicationWindow(index, index, index + 1, (), 0, "fixture") for index in range(10)]
    call_trace: list[tuple[str, int, int]] = []

    def fake_simulate_targets(
        replay_windows: list[PublicationWindow],
        _initial: dict[tuple[int, int], int],
        targets: list[SimulationTarget],
        *,
        measure_from: int,
    ) -> dict[str, SimulationResult]:
        phase = "tuning" if len(replay_windows) == 4 else "held-out"
        call_trace.append((phase, len(replay_windows), measure_from))
        assert [target.run_id for target in targets] == [
            candidate.candidate_id for candidate in candidates
        ]
        assert [target.strategy for target in targets] == [
            candidate.strategy for candidate in candidates
        ]
        tuning = len(replay_windows) == 4
        results = {}
        for target in targets:
            score = 50
            if tuning and target.strategy == "ReservedSlack-CSSC":
                score = 1 if target.config.reserved_slack_beta == 0.05 else 20
            if not tuning and target.strategy == "ReservedSlack-CSSC":
                score = 7 if target.config.reserved_slack_beta == 0.05 else 20
            if not tuning and target.strategy == "PeriodicRepack":
                score = 0 if target.config.periodic_repack_windows == 1 else 30
            results[target.run_id] = SimulationResult(
                StrategyMetrics(
                    target.strategy,
                    "reference",
                    windows=len(replay_windows) - measure_from,
                    update_encryptions=score,
                    source="persistent-state-predicted",
                ),
                {0: score},
            )
        return results

    real_select = select_tuned_fixed_candidate

    def observed_select(*args: object, **kwargs: object) -> FixedCandidate:
        call_trace.append(("freeze", -1, -1))
        return real_select(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(run_day1_suite, "select_tuned_fixed_candidate", observed_select)

    result = evaluate_causal_cell(
        windows=windows,
        initial_state={},
        base_config=SimulationConfig(
            rows=1,
            cols=1,
            effective_slots=8,
            partition_rows=1,
            matrix_value_bound=7,
            max_row_nnz=1,
            reserved_slack_beta=0.1,
            periodic_repack_windows=4,
            packed_coo_segment_capacity=128,
        ),
        split=(Fraction(1, 10), Fraction(3, 10), Fraction(3, 5)),
        candidates=candidates,
        costs=UnitCosts(),
        simulate_targets_fn=fake_simulate_targets,
    )

    assert call_trace == [
        ("tuning", 4, 1),
        ("freeze", -1, -1),
        ("held-out", 10, 4),
    ]
    assert result.selected_candidate_id == "reserved-slack/beta=0.05"
    assert result.oracle_candidate_id == "periodic-repack/windows=1"
    assert tuple(result.fixed_results) == tuple(candidate.candidate_id for candidate in candidates)
    assert result.tuned_policy.strategy == "TunedFixedPolicy"
    assert result.tuned_policy.update_encryptions == 7
    assert result.offline_oracle.strategy == "BestFixed-Offline-Oracle"
    assert result.offline_oracle.update_encryptions == 0


def test_three_window_cell_initializes_26_targets_and_advances_52_times(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidates = build_fixed_candidates(
        reserved_slack_betas=[0, 0.05, 0.1, 0.2, 0.4],
        periodic_repack_windows=[1, 4, 16, 64],
    )
    windows = [PublicationWindow(index, index, index + 1, (), 0, "fixture") for index in range(3)]
    init_count = 0
    advance_count = 0
    real_initialize = simulator_module.initialize_strategy
    real_advance = simulator_module.advance_publication

    def observed_initialize(*args: object, **kwargs: object):
        nonlocal init_count
        init_count += 1
        return real_initialize(*args, **kwargs)

    def observed_advance(*args: object, **kwargs: object):
        nonlocal advance_count
        advance_count += 1
        return real_advance(*args, **kwargs)

    monkeypatch.setattr(simulator_module, "initialize_strategy", observed_initialize)
    monkeypatch.setattr(simulator_module, "advance_publication", observed_advance)

    evaluate_causal_cell(
        windows=windows,
        initial_state={},
        base_config=SimulationConfig(
            rows=1,
            cols=1,
            effective_slots=128,
            partition_rows=1,
            matrix_value_bound=7,
            max_row_nnz=1,
            reserved_slack_beta=0.1,
            periodic_repack_windows=4,
            packed_coo_segment_capacity=128,
        ),
        split=(Fraction(0), Fraction(1, 3), Fraction(2, 3)),
        candidates=candidates,
        costs=UnitCosts(),
    )

    assert init_count == 26
    assert advance_count == 52


def test_suite_preflights_once_before_plan_and_materializes_each_cell_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    generated = 0
    windowized = 0
    initial_parameters: list[tuple[tuple[object, ...], dict[str, object]]] = []
    event_parameters: list[dict[str, object]] = []
    freshness_values: list[float] = []
    written: list[tuple[Path, list[object], dict[str, object]]] = []

    def fake_manifest(_path: object) -> dict[str, object]:
        calls.append("manifest")
        return {
            "freshness": {
                "max_seconds": 10.0,
                "microbatch_max_updates": 10,
                "query_requires_latest": True,
            },
            "packing": {"effective_slots": 8},
            "integer_correctness": {"matrix_entry_abs_bound": 7},
            "matrix": {"max_nnz_per_row": 4},
        }

    def fake_preflight(_manifest: object) -> PreflightReport:
        calls.append("preflight")
        return PreflightReport(
            status="pass",
            rows=257,
            cols=521,
            effective_slots=256,
            output_shares=2,
            observed_global_column_index=520,
            modulo_alias_column_index=8,
            global_gather_value=1,
            modulo_alias_value=0,
            reconstructed_matches_direct=True,
            reconstructed_high_row_value=1,
        )

    def fake_plan(_path: object) -> run_day1_suite.ExperimentPlan:
        calls.append("plan")
        return run_day1_suite.parse_experiment_plan(_small_experiment_plan())

    def fake_initial(*args: object, **kwargs: object) -> dict[tuple[int, int], int]:
        calls.append("initial")
        initial_parameters.append((args, kwargs))
        return {(0, 0): 5}

    def fake_events(*_args: object, **kwargs: object) -> list[Event]:
        nonlocal generated
        generated += 1
        event_parameters.append(kwargs)
        return [Event.set(float(index), 0, 1, 1) for index in range(10)]

    def fake_windows(*_args: object, **kwargs: object):
        nonlocal windowized
        windowized += 1
        freshness_values.append(float(kwargs["max_seconds"]))
        for index in range(10):
            updates = (NetUpdate(0, 0, 0, 1),) if index == 4 else ()
            yield PublicationWindow(index, index, index + 1, updates, 1, "fixture")

    def fake_cell(**kwargs: object) -> CausalCellResult:
        candidates = kwargs["candidates"]
        fixed = {}
        for index, candidate in enumerate(candidates):
            overflow_by_row = {}
            if index == 0:
                overflow_by_row = {0: 4}
            elif index == 1:
                overflow_by_row = {0: 1, 1: 1}
            fixed[candidate.candidate_id] = SimulationResult(
                StrategyMetrics(
                    candidate.strategy,
                    "reference",
                    source="persistent-state-predicted",
                ),
                overflow_by_row,
            )
        selected_id = candidates[0].candidate_id
        return CausalCellResult(
            warmup_end=1,
            tuning_end=4,
            tuning_results=fixed,
            fixed_results=fixed,
            selected_candidate_id=selected_id,
            tuned_policy=StrategyMetrics(
                "TunedFixedPolicy",
                "tuned-fixed-policy",
                source="tuning-prefix-frozen",
            ),
            oracle_candidate_id=selected_id,
            offline_oracle=StrategyMetrics(
                "BestFixed-Offline-Oracle",
                "diagnostic-oracle",
                source="held-out-hindsight-diagnostic",
            ),
        )

    monkeypatch.setattr(run_day1_suite, "load_manifest", fake_manifest)
    monkeypatch.setattr(run_day1_suite, "run_day1_preflight", fake_preflight)
    monkeypatch.setattr(run_day1_suite, "load_experiment_plan", fake_plan, raising=False)
    monkeypatch.setattr(run_day1_suite, "generate_initial_matrix", fake_initial)
    monkeypatch.setattr(run_day1_suite, "generate_event_stream", fake_events)
    monkeypatch.setattr(run_day1_suite, "publication_windows", fake_windows)
    monkeypatch.setattr(run_day1_suite, "evaluate_causal_cell", fake_cell)
    monkeypatch.setattr(
        run_day1_suite,
        "write_causal_records",
        lambda path, items, _costs, metadata: written.append((path, items, metadata)),
        raising=False,
    )
    monkeypatch.setattr(run_day1_suite, "write_causal_summary", lambda *_args: None, raising=False)
    monkeypatch.setattr(run_day1_suite, "write_causal_plots", lambda *_args: None)
    monkeypatch.setattr(run_day1_suite, "write_checksums", lambda *_args: None)

    args = argparse.Namespace(
        manifest="manifest.json",
        experiment_plan="plan.json",
        output_dir=tmp_path / "out",
        seed=7,
        rows=None,
        cols=None,
        nnz_per_row=None,
        updates=None,
    )

    assert run_suite(args) == 0
    assert calls == ["manifest", "preflight", "plan", "initial"]
    assert generated == 1
    assert windowized == 1
    assert initial_parameters == [((2, 2, 1), {"seed": 7, "matrix_entry_abs_bound": 7})]
    assert event_parameters == [
        {
            "rows": 2,
            "cols": 2,
            "update_count": 10,
            "seed": 8,
            "query_every": 0,
            "matrix_entry_abs_bound": 7,
        }
    ]
    assert freshness_values == [1.0]
    assert len(written) == 1
    path, items, metadata = written[0]
    assert path.relative_to(args.output_dir).as_posix() == "zipf/freshness-1s/rho-1"
    assert [item.record_kind for item in items].count("fixed-candidate") == 13
    assert [item.record_kind for item in items].count("tuned-fixed-policy") == 1
    assert [item.record_kind for item in items].count("diagnostic-oracle") == 1
    span80_by_candidate = metadata["span80_by_candidate"]
    assert isinstance(span80_by_candidate, dict)
    assert set(span80_by_candidate) == {
        candidate.candidate_id
        for candidate in run_day1_suite.parse_experiment_plan(_small_experiment_plan()).candidates
    }
    assert span80_by_candidate["padding-reuse"][1] == 0.5
    assert span80_by_candidate["mini-cssc-delta"][1] == 1.0
    suite_status = json.loads((args.output_dir / "SUITE_STATUS.json").read_text(encoding="utf-8"))
    assert suite_status["deferred_unpriced_plan_dimensions"] == ["bandwidth_profiles_mbps"]
    assert suite_status["planned_bandwidth_profiles_mbps"] == [100.0]


def test_suite_rejects_missing_plan_fields_before_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        run_day1_suite,
        "load_manifest",
        lambda _path: {
            "integer_correctness": {"matrix_entry_abs_bound": 7},
            "freshness": {"max_seconds": 1, "microbatch_max_updates": 1},
            "packing": {"effective_slots": 8},
            "matrix": {"max_nnz_per_row": 2},
        },
    )
    monkeypatch.setattr(
        run_day1_suite,
        "run_day1_preflight",
        lambda _manifest: PreflightReport(
            status="pass",
            rows=257,
            cols=521,
            effective_slots=256,
            output_shares=2,
            observed_global_column_index=520,
            modulo_alias_column_index=8,
            global_gather_value=1,
            modulo_alias_value=0,
            reconstructed_matches_direct=True,
            reconstructed_high_row_value=1,
        ),
    )
    incomplete_plan = _small_experiment_plan()
    del incomplete_plan["reserved_slack_betas"]
    monkeypatch.setattr(
        run_day1_suite,
        "load_experiment_plan",
        lambda _path: run_day1_suite.parse_experiment_plan(incomplete_plan),
    )
    monkeypatch.setattr(
        run_day1_suite,
        "generate_initial_matrix",
        lambda *_args, **_kwargs: pytest.fail("generation must not start"),
    )
    args = argparse.Namespace(
        manifest="manifest.json",
        experiment_plan="plan.json",
        output_dir=Path("unused"),
        seed=7,
        rows=None,
        cols=None,
        nnz_per_row=None,
        updates=None,
    )

    with pytest.raises(ValueError, match="experiment plan keys"):
        run_suite(args)
