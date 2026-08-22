from __future__ import annotations

import hashlib
import json
import re
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


def test_fraction_path_ids_are_exact_injection_safe_and_collision_free() -> None:
    first = Fraction(10_000_000_000_001, 10_000_000_000_000)
    second = Fraction(10_000_000_000_002, 10_000_000_000_000)

    assert format(float(first), ".12g") == format(float(second), ".12g")
    assert run_day1_suite.rho_path_id(Fraction(1, 10)) == "rho-n1d10"
    assert run_day1_suite.freshness_path_id(Fraction(1, 10)) == "freshness-n1d10s"
    assert run_day1_suite.rho_path_id(first) != run_day1_suite.rho_path_id(second)
    assert re.fullmatch(r"rho-n[0-9]+d[1-9][0-9]*", run_day1_suite.rho_path_id(first))


@pytest.mark.parametrize(
    "raw_seed",
    [
        "07",
        "+7",
        "-1",
        " 7",
        "7 ",
        "7\n",
        "7; touch injected",
        "9" * 1000,
        True,
    ],
)
def test_seed_parser_rejects_noncanonical_or_injectable_values(raw_seed: object) -> None:
    with pytest.raises(ValueError, match="canonical nonnegative integer"):
        run_day1_suite.parse_canonical_seed(raw_seed)


def test_seed_parser_returns_the_normalized_decimal_integer() -> None:
    assert run_day1_suite.parse_canonical_seed("0") == 0
    assert run_day1_suite.parse_canonical_seed("20260821") == 20_260_821


def test_runner_executes_each_ratio_from_experiment_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(
        json.dumps(
            {
                "plan_version": "0.2.0",
                "split": {"warmup": 0.1, "tuning": 0.3, "held_out": 0.6},
                "synthetic": {
                    "rows": 1,
                    "cols": 4,
                    "initial_nnz_per_row": 1,
                    "events": 4,
                    "effective_slots": 2048,
                    "partition_rows": 128,
                    "layout_measurement_kind": "synthetic-proxy",
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
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text('{"fixture": true}\n', encoding="utf-8")
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
            "freshness": {
                "max_seconds": 10.0,
                "microbatch_max_updates": 100,
                "query_requires_latest": True,
            },
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
        lambda path, _metrics, _costs, metadata, **_audit: records.append((path, metadata)),
    )
    monkeypatch.setattr(
        run_day1_suite,
        "write_causal_summary",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        run_day1_suite,
        "write_causal_plots",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "run_day1_suite.py",
            "--manifest",
            str(manifest_path),
            "--experiment-plan",
            str(plan_path),
            "--output-dir",
            str(output_dir),
            "--seed",
            "7",
            "--workload",
            "zipf",
            "--freshness-seconds",
            "1",
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
        "zipf/freshness-n1d1s/rho-n1d2",
        "zipf/freshness-n1d1s/rho-n2d1",
    ]
    assert not (output_dir / "SUITE_STATUS.json").exists()
    shard_status = json.loads((output_dir / "SHARD_STATUS.json").read_text(encoding="utf-8"))
    assert shard_status == {
        **shard_status,
        "schema": "day1-causal-predicted-v1",
        "state_model": "persistent-strategy-snapshots",
        "measurement_kind": "predicted-proxy",
        "gate_eligible": False,
        "complete_cost_claim_allowed": False,
        "complete_reference_set": False,
        "suite_complete": False,
        "seed": 7,
        "workload": "zipf",
        "freshness_seconds_fraction": "1",
        "rho_ids": ["rho-n1d2", "rho-n2d1"],
        "cells_expected": 2,
        "cells_completed": 2,
        "experiment_plan_sha256": hashlib.sha256(plan_path.read_bytes()).hexdigest(),
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
    }
    assert "strong-packed-coo" in shard_status["deferred_reference_baselines"]

    first_path, first_metadata = records[0]
    trace_path = first_path / "event-window-trace.jsonl"
    trace_bytes = trace_path.read_bytes()
    trace_records = [json.loads(line) for line in trace_bytes.splitlines()]
    assert trace_bytes == b"".join(
        (json.dumps(item, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode(
            "utf-8"
        )
        for item in trace_records
    )
    assert trace_records[0]["record_type"] == "header"
    assert trace_records[0]["cell"] == {
        "freshness_seconds_fraction": "1",
        "rho_fraction": "1/2",
        "rho_id": "rho-n1d2",
        "workload": "zipf",
    }
    assert trace_records[0]["experiment_plan_sha256"] == shard_status["experiment_plan_sha256"]
    assert trace_records[0]["manifest_sha256"] == shard_status["manifest_sha256"]
    assert trace_records[0]["seed"] == 7
    assert trace_records[0]["matrix"] == {
        "cols": 4,
        "initial_nnz_per_row": 1,
        "rows": 1,
    }
    assert trace_records[0]["schema"] == "day1-event-window-trace-v2"
    assert trace_records[0]["effective_slots"] == 2048
    assert trace_records[0]["partition_rows"] == 128
    assert trace_records[0]["layout_measurement_kind"] == "synthetic-proxy"
    assert trace_records[0]["query_requires_latest"] is True
    assert trace_records[0]["microbatch_max_updates"] == 100
    assert trace_records[0]["split"] == {
        "held_out": "3/5",
        "tuning": "3/10",
        "warmup": "1/10",
    }
    assert trace_records[0]["window_count"] == len(trace_records) - 1
    assert [item["position"] for item in trace_records[1:]] == list(range(len(trace_records) - 1))
    assert all(
        set(item)
        == {
            "end",
            "index",
            "position",
            "query_count",
            "reason",
            "record_type",
            "start",
            "updates",
        }
        for item in trace_records[1:]
    )
    assert all(
        set(update) == {"after", "before", "col", "row"}
        for item in trace_records[1:]
        for update in item["updates"]
    )
    assert first_metadata["event_window_trace_sha256"] == hashlib.sha256(trace_bytes).hexdigest()


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
            "--workload",
            "zipf",
            "--freshness-seconds",
            "1",
        ],
    )

    with pytest.raises(Day1PreflightError, match="preflight failed"):
        run_day1_suite.main()
