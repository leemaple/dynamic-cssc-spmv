from __future__ import annotations

import json
from fractions import Fraction
from pathlib import Path

import pytest

from dynamic_cssc.events import Event, EventKind
from dynamic_cssc.metrics import StrategyMetrics
from dynamic_cssc.preflight import Day1PreflightError, PreflightReport
from dynamic_cssc.simulator import SimulationResult
from scripts import run_day1_suite
from scripts.run_day1_suite import CausalCellResult, insert_queries_by_ratio


@pytest.mark.parametrize(
    "ratio",
    [
        Fraction(1, 100),
        Fraction(3, 100),
        Fraction(1, 10),
        Fraction(3, 10),
        Fraction(1),
        Fraction(3),
        Fraction(10),
        Fraction(30),
        Fraction(100),
    ],
)
def test_fraction_scheduler_inserts_exact_grid_query_totals(ratio: Fraction) -> None:
    updates = [Event.set(index / 100, 0, index, 1) for index in range(200)]

    scheduled = insert_queries_by_ratio(updates, ratio)

    assert sum(event.kind == EventKind.SET for event in scheduled) == 200
    assert sum(event.kind == EventKind.QUERY for event in scheduled) == 200 * ratio
    assert [event.timestamp for event in scheduled] == sorted(
        event.timestamp for event in scheduled
    )


def test_runner_executes_each_ratio_from_experiment_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(
        json.dumps(
            {
                "plan_version": "0.1.0",
                "split": {"warmup": 0.1, "tuning": 0.3, "held_out": 0.6},
                "synthetic": {
                    "rows": 1,
                    "cols": 4,
                    "initial_nnz_per_row": 1,
                    "events": 4,
                    "queries_per_update_grid": [0.5, 2.0],
                    "workloads": ["zipf"],
                },
                "reserved_slack_betas": [0, 0.05, 0.1, 0.2, 0.4],
                "periodic_repack_windows": [1, 4, 16, 64],
                "freshness_seconds": [1.0],
                "bandwidth_profiles_mbps": [100],
            }
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "out"
    query_every_values: list[int] = []
    value_bounds: list[int] = []
    call_order: list[str] = []
    records: list[tuple[Path, dict[str, object]]] = []

    def fake_preflight(_manifest: object) -> PreflightReport:
        call_order.append("preflight")
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

    monkeypatch.setattr(run_day1_suite, "run_day1_preflight", fake_preflight, raising=False)
    monkeypatch.setattr(
        run_day1_suite,
        "load_manifest",
        lambda _path: {
            "freshness": {"max_seconds": 10.0, "microbatch_max_updates": 100},
            "packing": {"effective_slots": 8},
            "integer_correctness": {"matrix_entry_abs_bound": 7},
        },
    )

    def fake_generate_initial_matrix(
        *_args: object, **kwargs: object
    ) -> dict[tuple[int, int], int]:
        call_order.append("generate-initial")
        value_bounds.append(int(kwargs["matrix_entry_abs_bound"]))
        return {(0, 0): 1}

    monkeypatch.setattr(run_day1_suite, "generate_initial_matrix", fake_generate_initial_matrix)

    def fake_generate_event_stream(*_args: object, **kwargs: object) -> list[Event]:
        query_every_values.append(int(kwargs["query_every"]))
        value_bounds.append(int(kwargs["matrix_entry_abs_bound"]))
        return [Event.set(float(index), 0, index, 1) for index in range(4)]

    monkeypatch.setattr(run_day1_suite, "generate_event_stream", fake_generate_event_stream)

    def fake_cell(**kwargs: object) -> CausalCellResult:
        candidates = kwargs["candidates"]
        fixed = {
            candidate.candidate_id: SimulationResult(
                StrategyMetrics(
                    candidate.strategy,
                    "reference",
                    source="persistent-state-predicted",
                ),
                {},
            )
            for candidate in candidates
        }
        selected_id = candidates[0].candidate_id
        return CausalCellResult(
            warmup_end=0,
            tuning_end=1,
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

    monkeypatch.setattr(run_day1_suite, "evaluate_causal_cell", fake_cell)
    monkeypatch.setattr(
        run_day1_suite,
        "write_causal_records",
        lambda path, _metrics, _costs, metadata: records.append((path, metadata)),
    )
    monkeypatch.setattr(run_day1_suite, "write_causal_summary", lambda *_args: None)
    monkeypatch.setattr(run_day1_suite, "write_causal_plots", lambda *_args: None)
    monkeypatch.setattr(run_day1_suite, "write_checksums", lambda *_args: None)
    monkeypatch.setattr(
        "sys.argv",
        [
            "run_day1_suite.py",
            "--manifest",
            "unused.json",
            "--experiment-plan",
            str(plan_path),
            "--output-dir",
            str(output_dir),
            "--seed",
            "7",
            "--rows",
            "1",
            "--cols",
            "4",
            "--updates",
            "4",
        ],
    )

    assert run_day1_suite.main() == 0
    assert call_order[:2] == ["preflight", "generate-initial"]
    assert query_every_values == [0, 0]
    assert value_bounds == [7, 7, 7]
    assert [metadata["queries_per_update_target"] for _, metadata in records] == [
        0.5,
        2.0,
    ]
    assert [metadata["queries_total"] for _, metadata in records] == [2, 8]
    assert [path.relative_to(output_dir).as_posix() for path, _ in records] == [
        "zipf/freshness-1s/rho-0p5",
        "zipf/freshness-1s/rho-2",
    ]


def test_runner_fails_before_workload_generation_when_preflight_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(
        json.dumps(
            {
                "split": {"warmup": 0.0, "tuning": 0.0, "held_out": 1.0},
                "synthetic": {"queries_per_update_grid": [1.0]},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(run_day1_suite, "load_manifest", lambda _path: {})
    monkeypatch.setattr(
        run_day1_suite,
        "run_day1_preflight",
        lambda _manifest: (_ for _ in ()).throw(Day1PreflightError("preflight failed")),
        raising=False,
    )
    monkeypatch.setattr(
        run_day1_suite,
        "generate_initial_matrix",
        lambda *_args, **_kwargs: pytest.fail("workload generation must not run"),
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "run_day1_suite.py",
            "--manifest",
            "unused.json",
            "--experiment-plan",
            str(plan_path),
            "--output-dir",
            str(tmp_path / "out"),
            "--seed",
            "7",
        ],
    )

    with pytest.raises(Day1PreflightError, match="preflight failed"):
        run_day1_suite.main()
