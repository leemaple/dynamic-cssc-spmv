from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import replace
from fractions import Fraction
from functools import cache
from pathlib import Path

import pytest

from dynamic_cssc.events import EventKind, PublicationWindow, publication_windows
from dynamic_cssc.metrics import StrategyMetrics, UnitCosts
from dynamic_cssc.report import CausalMetricRecord, write_causal_records
from dynamic_cssc.selection import split_boundaries
from dynamic_cssc.workloads import generate_event_stream, generate_initial_matrix
from scripts import aggregate_day1_shards
from scripts.run_day1_suite import (
    EVENT_WINDOW_TRACE_SCHEMA,
    ExperimentPlan,
    freshness_path_id,
    insert_queries_by_ratio,
    load_experiment_plan,
    rho_path_id,
    write_event_window_trace,
)

ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = ROOT / "config" / "experiment_plan.json"
MANIFEST_PATH = ROOT / "config" / "params_manifest.json"
SEED = 20260821
FIXTURE_ROWS = 8
FIXTURE_COLS = 8
FIXTURE_INITIAL_NNZ_PER_ROW = 1
FIXTURE_EVENTS = 130
REQUIRED_CELL_FILES = (
    "SUMMARY.md",
    "event-window-trace.jsonl",
    "metrics.csv",
    "metrics.json",
    "t_rho_proxy.png",
    "tuning_aggregates.csv",
    "ua_vs_qa_proxy.png",
)
PREFLIGHT = {
    "status": "pass",
    "rows": 257,
    "cols": 521,
    "effective_slots": 256,
    "output_shares": 2,
    "observed_global_column_index": 520,
    "modulo_alias_column_index": 8,
    "global_gather_value": 1,
    "modulo_alias_value": 0,
    "reconstructed_matches_direct": True,
    "reconstructed_high_row_value": 1,
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture_plan_path(download_dir: Path) -> Path:
    path = download_dir.parent / "experiment-plan-small.json"
    if path.exists():
        return path
    payload = json.loads(PLAN_PATH.read_text(encoding="utf-8"))
    payload["synthetic"].update(
        {
            "rows": FIXTURE_ROWS,
            "cols": FIXTURE_COLS,
            "initial_nnz_per_row": FIXTURE_INITIAL_NNZ_PER_ROW,
            "events": FIXTURE_EVENTS,
        }
    )
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, allow_nan=False),
        encoding="utf-8",
    )
    return path


@cache
def _fixture_stream(
    workload: str,
    workload_seed: int,
    freshness: Fraction,
    ratio: Fraction,
    rows: int,
    cols: int,
    initial_nnz_per_row: int,
    events_planned: int,
    matrix_entry_abs_bound: int,
    microbatch_max_updates: int,
    query_requires_latest: bool,
) -> tuple[tuple[PublicationWindow, ...], int, int]:
    initial_state = generate_initial_matrix(
        rows,
        cols,
        initial_nnz_per_row,
        seed=SEED,
        matrix_entry_abs_bound=matrix_entry_abs_bound,
    )
    base_events = generate_event_stream(
        workload,
        initial_state,
        rows=rows,
        cols=cols,
        update_count=events_planned,
        seed=workload_seed,
        query_every=0,
        matrix_entry_abs_bound=matrix_entry_abs_bound,
    )
    scheduled = insert_queries_by_ratio(base_events, ratio)
    windows = tuple(
        publication_windows(
            scheduled,
            initial_state,
            max_seconds=float(freshness),
            microbatch_max_updates=microbatch_max_updates,
            query_requires_latest=query_requires_latest,
        )
    )
    return (
        windows,
        sum(event.kind == EventKind.SET for event in scheduled),
        sum(event.kind == EventKind.QUERY for event in scheduled),
    )


def _canonical_jsonl(records: list[dict[str, object]]) -> bytes:
    return b"".join(
        (json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode(
            "utf-8"
        )
        for record in records
    )


def _initial_state_sha256(state: dict[tuple[int, int], int]) -> str:
    entries = [
        {"row": row, "col": col, "value": value} for (row, col), value in sorted(state.items())
    ]
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
        "utf-8"
    )
    return hashlib.sha256(canonical).hexdigest()


def _write_checksums(directory: Path, filenames: tuple[str, ...]) -> None:
    lines = [f"{_sha256(directory / name)}  {name}" for name in sorted(filenames)]
    (directory / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_cell(
    shard_dir: Path,
    *,
    workload: str,
    workload_seed: int,
    freshness: Fraction,
    ratio: Fraction,
    plan: ExperimentPlan,
    plan_sha256: str,
    manifest_sha256: str,
    candidate_ids: list[str],
    initial_state_sha256: str,
    microbatch_max_updates: int,
    query_requires_latest: bool,
    matrix_entry_abs_bound: int,
) -> dict[str, object]:
    freshness_id = freshness_path_id(freshness)
    rho_id = rho_path_id(ratio)
    relative_path = Path(workload) / freshness_id / rho_id
    cell_dir = shard_dir / relative_path
    cell_dir.mkdir(parents=True)

    windows, update_events_total, queries_total = _fixture_stream(
        workload,
        workload_seed,
        freshness,
        ratio,
        plan.rows,
        plan.cols,
        plan.initial_nnz_per_row,
        plan.events,
        matrix_entry_abs_bound,
        microbatch_max_updates,
        query_requires_latest,
    )
    warmup_end, tuning_end = split_boundaries(len(windows), plan.split)
    tuning_windows = windows[warmup_end:tuning_end]
    held_out_windows = windows[tuning_end:]
    trace_path = cell_dir / "event-window-trace.jsonl"
    trace_sha256 = write_event_window_trace(
        trace_path,
        windows=list(windows),
        workload=workload,
        freshness_seconds=freshness,
        ratio=ratio,
        experiment_plan_sha256=plan_sha256,
        manifest_sha256=manifest_sha256,
        seed=SEED,
        workload_seed=workload_seed,
        rows=plan.rows,
        cols=plan.cols,
        initial_nnz_per_row=plan.initial_nnz_per_row,
        effective_slots=plan.effective_slots,
        partition_rows=plan.partition_rows,
        layout_measurement_kind=plan.layout_measurement_kind,
        initial_state_sha256=initial_state_sha256,
        microbatch_max_updates=microbatch_max_updates,
        query_requires_latest=query_requires_latest,
        split=plan.split,
    )

    candidates_by_id = {candidate.candidate_id: candidate for candidate in plan.candidates}
    canonical_candidate_ids = sorted(candidates_by_id)
    selected_candidate_id = canonical_candidate_ids[0]
    oracle_candidate_id = canonical_candidate_ids[0]
    metadata = {
        "workload": workload,
        "suite_seed": SEED,
        "freshness_seconds_fraction": str(freshness),
        "queries_per_update_fraction": str(ratio),
        "rho_id": rho_id,
        "experiment_plan_sha256": plan_sha256,
        "manifest_sha256": manifest_sha256,
        "event_window_trace_schema": EVENT_WINDOW_TRACE_SCHEMA,
        "event_window_trace_sha256": trace_sha256,
        "seed": workload_seed,
        "rows": plan.rows,
        "cols": plan.cols,
        "initial_nnz_per_row": plan.initial_nnz_per_row,
        "events_planned": plan.events,
        "effective_slots": plan.effective_slots,
        "partition_rows": plan.partition_rows,
        "layout_measurement_kind": plan.layout_measurement_kind,
        "freshness_seconds": float(freshness),
        "queries_per_update_target": float(ratio),
        "queries_per_update_scheduled": (
            queries_total / update_events_total if update_events_total else 0.0
        ),
        "update_events_total": update_events_total,
        "queries_total": queries_total,
        "held_out_queries": sum(window.query_count for window in held_out_windows),
        "windows_total": len(windows),
        "warmup_windows": warmup_end,
        "tuning_windows": len(tuning_windows),
        "held_out_windows": len(held_out_windows),
        "fixed_candidate_count": 13,
        "span80_by_candidate": {
            candidate_id: {"1": 0.0, "2": 0.0, "4": 0.0, "8": 0.0} for candidate_id in candidate_ids
        },
        "initial_state_sha256": initial_state_sha256,
        "real_temporal_dataset": False,
        "selected_candidate_id": selected_candidate_id,
        "oracle_candidate_id": oracle_candidate_id,
        "state_model": "persistent-strategy-snapshots",
        "measurement_kind": "predicted-proxy",
        "gate_eligible": False,
        "complete_cost_claim_allowed": False,
        "complete_reference_set": False,
    }
    fixed_records: list[CausalMetricRecord] = []
    tuning_results: dict[str, StrategyMetrics] = {}
    for index, candidate_id in enumerate(canonical_candidate_ids):
        strategy = candidates_by_id[candidate_id].strategy
        fixed_records.append(
            CausalMetricRecord(
                "fixed-candidate",
                candidate_id,
                candidate_id,
                strategy,
                "fixed-candidate",
                StrategyMetrics(
                    strategy,
                    "reference",
                    windows=len(held_out_windows),
                    queries=sum(window.query_count for window in held_out_windows),
                    updates=sum(len(window.updates) for window in held_out_windows),
                    update_encryptions=index + 1,
                    source="persistent-state-predicted",
                ),
            )
        )
        tuning_results[candidate_id] = StrategyMetrics(
            strategy,
            "reference",
            windows=len(tuning_windows),
            queries=sum(window.query_count for window in tuning_windows),
            updates=sum(len(window.updates) for window in tuning_windows),
            update_encryptions=index + 1,
            source="persistent-state-predicted",
        )
    selected_basis = fixed_records[0]
    tuned_record = CausalMetricRecord(
        "tuned-fixed-policy",
        selected_candidate_id,
        "TunedFixedPolicy",
        selected_basis.strategy_kind,
        "tuning-prefix-only",
        replace(
            selected_basis.metrics,
            strategy="TunedFixedPolicy",
            category="tuned-fixed-policy",
            source="tuning-prefix-frozen",
        ),
    )
    oracle_record = CausalMetricRecord(
        "diagnostic-oracle",
        oracle_candidate_id,
        "BestFixed-Offline-Oracle",
        selected_basis.strategy_kind,
        "held-out-hindsight-diagnostic-only",
        replace(
            selected_basis.metrics,
            strategy="BestFixed-Offline-Oracle",
            category="diagnostic-oracle",
            source="held-out-hindsight-diagnostic",
        ),
    )
    write_causal_records(
        cell_dir,
        [*fixed_records, tuned_record, oracle_record],
        UnitCosts(),
        metadata,
        tuning_results=tuning_results,
        selected_candidate_id=selected_candidate_id,
        oracle_candidate_id=oracle_candidate_id,
    )
    (cell_dir / "SUMMARY.md").write_text("# fixture\n", encoding="utf-8")
    (cell_dir / "t_rho_proxy.png").write_bytes(b"fixture-t-rho")
    (cell_dir / "ua_vs_qa_proxy.png").write_bytes(b"fixture-ua-qa")
    _write_checksums(cell_dir, REQUIRED_CELL_FILES)
    return {
        "relative_path": relative_path.as_posix(),
        "rho_id": rho_id,
        "rho_fraction": str(ratio),
        "event_window_trace_sha256": trace_sha256,
        "cell_checksums_sha256": _sha256(cell_dir / "SHA256SUMS"),
    }


def _write_root_checksums(shard_dir: Path) -> None:
    paths = sorted(
        path for path in shard_dir.rglob("*") if path.is_file() and path.name != "SHA256SUMS"
    )
    lines = [f"{_sha256(path)}  {path.relative_to(shard_dir).as_posix()}" for path in paths]
    (shard_dir / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _build_download_layout(download_dir: Path) -> list[Path]:
    plan_path = _fixture_plan_path(download_dir)
    plan = load_experiment_plan(plan_path)
    assert (len(plan.workloads), len(plan.freshness_seconds), len(plan.ratio_grid)) == (7, 3, 9)
    plan_sha256 = _sha256(plan_path)
    manifest_sha256 = _sha256(MANIFEST_PATH)
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    initial_state = generate_initial_matrix(
        plan.rows,
        plan.cols,
        plan.initial_nnz_per_row,
        seed=SEED,
        matrix_entry_abs_bound=manifest["integer_correctness"]["matrix_entry_abs_bound"],
    )
    initial_state_digest = _initial_state_sha256(initial_state)
    candidate_ids = [candidate.candidate_id for candidate in plan.candidates]
    shards: list[Path] = []
    for shard_index, (workload, freshness) in enumerate(
        (workload, freshness) for workload in plan.workloads for freshness in plan.freshness_seconds
    ):
        shard_dir = download_dir / f"artifact-{shard_index:02d}"
        shard_dir.mkdir(parents=True)
        workload_seed = SEED + plan.workloads.index(workload) + 1
        cells = [
            _write_cell(
                shard_dir,
                workload=workload,
                workload_seed=workload_seed,
                freshness=freshness,
                ratio=ratio,
                plan=plan,
                plan_sha256=plan_sha256,
                manifest_sha256=manifest_sha256,
                candidate_ids=candidate_ids,
                initial_state_sha256=initial_state_digest,
                microbatch_max_updates=manifest["freshness"]["microbatch_max_updates"],
                query_requires_latest=manifest["freshness"]["query_requires_latest"],
                matrix_entry_abs_bound=manifest["integer_correctness"]["matrix_entry_abs_bound"],
            )
            for ratio in plan.ratio_grid
        ]
        status = {
            "schema": "day1-causal-predicted-v1",
            "state_model": "persistent-strategy-snapshots",
            "measurement_kind": "predicted-proxy",
            "gate_eligible": False,
            "complete_cost_claim_allowed": False,
            "complete_reference_set": False,
            "suite_complete": False,
            "deferred_reference_baselines": ["strong-packed-coo"],
            "seed": SEED,
            "experiment_plan_sha256": plan_sha256,
            "manifest_sha256": manifest_sha256,
            "experiment_plan_version": plan.plan_version,
            "workload": workload,
            "freshness_seconds": float(freshness),
            "freshness_seconds_fraction": str(freshness),
            "rho_ids": [rho_path_id(ratio) for ratio in plan.ratio_grid],
            "cells_expected": 9,
            "cells_completed": 9,
            "candidate_ids": sorted(candidate_ids),
            "effective_slots": plan.effective_slots,
            "partition_rows": plan.partition_rows,
            "layout_measurement_kind": plan.layout_measurement_kind,
            "planned_bandwidth_profiles_mbps": [
                float(value) for value in plan.bandwidth_profiles_mbps
            ],
            "deferred_unpriced_plan_dimensions": ["bandwidth_profiles_mbps"],
            "preflight": PREFLIGHT,
            "cells": cells,
        }
        (shard_dir / "SHARD_STATUS.json").write_text(
            json.dumps(status, sort_keys=True), encoding="utf-8"
        )
        _write_root_checksums(shard_dir)
        shards.append(shard_dir)
    return shards


def _resign_cell_and_shard(shard_dir: Path, cell_dir: Path) -> None:
    trace_sha256 = _sha256(cell_dir / "event-window-trace.jsonl")
    metrics_path = cell_dir / "metrics.json"
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    metrics["metadata"]["event_window_trace_sha256"] = trace_sha256
    metrics_path.write_text(json.dumps(metrics, sort_keys=True), encoding="utf-8")
    _write_checksums(cell_dir, REQUIRED_CELL_FILES)
    status_path = shard_dir / "SHARD_STATUS.json"
    status = json.loads(status_path.read_text(encoding="utf-8"))
    relative_path = cell_dir.relative_to(shard_dir).as_posix()
    cell_status = next(cell for cell in status["cells"] if cell["relative_path"] == relative_path)
    cell_status["event_window_trace_sha256"] = trace_sha256
    cell_status["cell_checksums_sha256"] = _sha256(cell_dir / "SHA256SUMS")
    status_path.write_text(json.dumps(status, sort_keys=True), encoding="utf-8")
    _write_root_checksums(shard_dir)


def test_aggregator_accepts_only_the_complete_21_shard_189_cell_cartesian_product(
    tmp_path: Path,
) -> None:
    download_dir = tmp_path / "downloaded-shards"
    shards = _build_download_layout(download_dir)
    output_dir = tmp_path / "day1"

    status = aggregate_day1_shards.aggregate_shards(
        shards_dir=download_dir,
        output_dir=output_dir,
        experiment_plan=_fixture_plan_path(download_dir),
        manifest=MANIFEST_PATH,
        seed=SEED,
    )

    assert len(shards) == 21
    assert status["suite_complete"] is True
    assert status["complete_reference_set"] is False
    assert status["shards_expected"] == status["shards_completed"] == 21
    assert status["cells_expected"] == status["cells_completed"] == 189
    assert len(status["cell_ids"]) == len(set(status["cell_ids"])) == 189
    assert status["experiment_plan_sha256"] == _sha256(_fixture_plan_path(download_dir))
    assert status["manifest_sha256"] == _sha256(MANIFEST_PATH)
    assert status["effective_slots"] == 2048
    assert status["partition_rows"] == 128
    assert status["layout_measurement_kind"] == "synthetic-proxy"
    assert status["planned_bandwidth_profiles_mbps"] == [100.0, 1000.0, 10000.0]
    assert status["deferred_unpriced_plan_dimensions"] == ["bandwidth_profiles_mbps"]
    assert status["preflight"] == PREFLIGHT
    assert (output_dir / "SUITE_STATUS.json").is_file()
    assert (output_dir / "SHA256SUMS").is_file()
    assert not (output_dir / "SHARD_STATUS.json").exists()
    checksummed_paths = {
        line.split("  ", 1)[1]
        for line in (output_dir / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    }
    output_files = {
        path.relative_to(output_dir).as_posix()
        for path in output_dir.rglob("*")
        if path.is_file() and path != output_dir / "SHA256SUMS"
    }
    assert checksummed_paths == output_files
    assert len(checksummed_paths) == 1 + 189 * 8


def test_aggregator_cli_loads_when_executed_by_workflow_script_path() -> None:
    environment = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

    completed = subprocess.run(
        [sys.executable, "scripts/aggregate_day1_shards.py", "--help"],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "downloaded-shards/<artifact-name>/SHARD_STATUS.json" in completed.stdout


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("missing-shard", "exactly 21 shard artifacts"),
        ("duplicate-shard", "duplicate shard identity"),
        ("duplicate-cell", "rho_ids|duplicate cell"),
        ("seed", "seed"),
        ("schema", "schema"),
        ("manifest-digest", "manifest_sha256"),
        ("missing-file", "exact required file set"),
        ("bad-checksum", "checksum mismatch"),
    ],
)
def test_aggregator_fails_closed_before_writing_suite_status(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    download_dir = tmp_path / "downloaded-shards"
    shards = _build_download_layout(download_dir)
    if mutation == "missing-shard":
        shutil.rmtree(shards[-1])
    elif mutation == "duplicate-shard":
        shutil.rmtree(shards[-1])
        shutil.copytree(shards[0], shards[-1])
    elif mutation == "duplicate-cell":
        status_path = shards[0] / "SHARD_STATUS.json"
        status = json.loads(status_path.read_text(encoding="utf-8"))
        status["rho_ids"][1] = status["rho_ids"][0]
        status["cells"][1] = dict(status["cells"][0])
        status_path.write_text(json.dumps(status, sort_keys=True), encoding="utf-8")
    elif mutation in {"seed", "schema", "manifest-digest"}:
        status_path = shards[0] / "SHARD_STATUS.json"
        status = json.loads(status_path.read_text(encoding="utf-8"))
        key, value = {
            "seed": ("seed", SEED + 1),
            "schema": ("schema", "wrong-schema"),
            "manifest-digest": ("manifest_sha256", "0" * 64),
        }[mutation]
        status[key] = value
        status_path.write_text(json.dumps(status, sort_keys=True), encoding="utf-8")
    else:
        cell_dir = next(path.parent for path in shards[0].rglob("metrics.json"))
        summary = cell_dir / "SUMMARY.md"
        if mutation == "missing-file":
            summary.unlink()
        else:
            summary.write_text("tampered after checksums\n", encoding="utf-8")

    output_dir = tmp_path / "day1"
    with pytest.raises(ValueError, match=message):
        aggregate_day1_shards.aggregate_shards(
            shards_dir=download_dir,
            output_dir=output_dir,
            experiment_plan=_fixture_plan_path(download_dir),
            manifest=MANIFEST_PATH,
            seed=SEED,
        )

    assert not (output_dir / "SUITE_STATUS.json").exists()


def test_aggregator_rejects_an_unchecksummed_extra_cell_file(tmp_path: Path) -> None:
    download_dir = tmp_path / "downloaded-shards"
    shards = _build_download_layout(download_dir)
    cell_dir = next(path.parent for path in shards[0].rglob("metrics.json"))
    (cell_dir / "rogue-unchecksummed.txt").write_text("not evidence\n", encoding="utf-8")
    output_dir = tmp_path / "day1"

    with pytest.raises(ValueError, match="exact required file set"):
        aggregate_day1_shards.aggregate_shards(
            shards_dir=download_dir,
            output_dir=output_dir,
            experiment_plan=_fixture_plan_path(download_dir),
            manifest=MANIFEST_PATH,
            seed=SEED,
        )

    assert not (output_dir / "SUITE_STATUS.json").exists()


def test_aggregator_rejects_an_extra_checksum_alias(tmp_path: Path) -> None:
    download_dir = tmp_path / "downloaded-shards"
    shards = _build_download_layout(download_dir)
    cell_dir = next(path.parent for path in shards[0].rglob("metrics.json"))
    checksums_path = cell_dir / "SHA256SUMS"
    checksums_path.write_text(
        checksums_path.read_text(encoding="utf-8")
        + f"{_sha256(cell_dir / 'metrics.json')}  ./metrics.json\n",
        encoding="utf-8",
    )
    status_path = shards[0] / "SHARD_STATUS.json"
    status = json.loads(status_path.read_text(encoding="utf-8"))
    relative_path = cell_dir.relative_to(shards[0]).as_posix()
    cell_status = next(cell for cell in status["cells"] if cell["relative_path"] == relative_path)
    cell_status["cell_checksums_sha256"] = _sha256(checksums_path)
    status_path.write_text(json.dumps(status, sort_keys=True), encoding="utf-8")
    _write_root_checksums(shards[0])
    output_dir = tmp_path / "day1"

    with pytest.raises(ValueError, match="exact required checksum paths"):
        aggregate_day1_shards.aggregate_shards(
            shards_dir=download_dir,
            output_dir=output_dir,
            experiment_plan=_fixture_plan_path(download_dir),
            manifest=MANIFEST_PATH,
            seed=SEED,
        )

    assert not (output_dir / "SUITE_STATUS.json").exists()


def test_aggregator_rejects_a_symlinked_required_cell_file(tmp_path: Path) -> None:
    download_dir = tmp_path / "downloaded-shards"
    shards = _build_download_layout(download_dir)
    cell_dir = next(path.parent for path in shards[0].rglob("metrics.json"))
    summary_path = cell_dir / "SUMMARY.md"
    external_summary = tmp_path / "external-summary.md"
    external_summary.write_bytes(summary_path.read_bytes())
    summary_path.unlink()
    summary_path.symlink_to(external_summary)
    output_dir = tmp_path / "day1"

    with pytest.raises(ValueError, match="regular files without symlinks"):
        aggregate_day1_shards.aggregate_shards(
            shards_dir=download_dir,
            output_dir=output_dir,
            experiment_plan=_fixture_plan_path(download_dir),
            manifest=MANIFEST_PATH,
            seed=SEED,
        )

    assert not (output_dir / "SUITE_STATUS.json").exists()


def test_aggregator_rejects_an_extra_shard_root_file(tmp_path: Path) -> None:
    download_dir = tmp_path / "downloaded-shards"
    shards = _build_download_layout(download_dir)
    (shards[0] / "rogue-root.txt").write_text("not evidence\n", encoding="utf-8")
    output_dir = tmp_path / "day1"

    with pytest.raises(ValueError, match="exact artifact tree"):
        aggregate_day1_shards.aggregate_shards(
            shards_dir=download_dir,
            output_dir=output_dir,
            experiment_plan=_fixture_plan_path(download_dir),
            manifest=MANIFEST_PATH,
            seed=SEED,
        )

    assert not (output_dir / "SUITE_STATUS.json").exists()


def test_aggregator_rejects_an_extra_shard_directory(tmp_path: Path) -> None:
    download_dir = tmp_path / "downloaded-shards"
    shards = _build_download_layout(download_dir)
    (shards[0] / "rogue-directory").mkdir()

    with pytest.raises(ValueError, match="exact artifact tree"):
        aggregate_day1_shards.aggregate_shards(
            shards_dir=download_dir,
            output_dir=tmp_path / "day1",
            experiment_plan=_fixture_plan_path(download_dir),
            manifest=MANIFEST_PATH,
            seed=SEED,
        )


def test_aggregator_rejects_an_extra_root_checksum_alias(tmp_path: Path) -> None:
    download_dir = tmp_path / "downloaded-shards"
    shards = _build_download_layout(download_dir)
    checksums_path = shards[0] / "SHA256SUMS"
    checksums_path.write_text(
        checksums_path.read_text(encoding="utf-8")
        + f"{_sha256(shards[0] / 'SHARD_STATUS.json')}  ./SHARD_STATUS.json\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exact root checksum paths"):
        aggregate_day1_shards.aggregate_shards(
            shards_dir=download_dir,
            output_dir=tmp_path / "day1",
            experiment_plan=_fixture_plan_path(download_dir),
            manifest=MANIFEST_PATH,
            seed=SEED,
        )


def test_aggregator_rejects_nonartifact_entries_in_download_root(tmp_path: Path) -> None:
    download_dir = tmp_path / "downloaded-shards"
    _build_download_layout(download_dir)
    (download_dir / "ignored.txt").write_text("must not be ignored\n", encoding="utf-8")

    with pytest.raises(ValueError, match="exactly 21 shard artifacts as regular directories"):
        aggregate_day1_shards.aggregate_shards(
            shards_dir=download_dir,
            output_dir=tmp_path / "day1",
            experiment_plan=_fixture_plan_path(download_dir),
            manifest=MANIFEST_PATH,
            seed=SEED,
        )


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("planned_bandwidth_profiles_mbps", [100.0]),
        ("deferred_unpriced_plan_dimensions", []),
        ("preflight", {**PREFLIGHT, "status": "fail"}),
        ("effective_slots", 2049),
        ("partition_rows", 129),
        ("layout_measurement_kind", "measured"),
    ],
)
def test_aggregator_rejects_status_dimensions_that_contradict_frozen_sources(
    tmp_path: Path,
    field: str,
    invalid_value: object,
) -> None:
    download_dir = tmp_path / "downloaded-shards"
    shards = _build_download_layout(download_dir)
    status_path = shards[0] / "SHARD_STATUS.json"
    status = json.loads(status_path.read_text(encoding="utf-8"))
    status[field] = invalid_value
    status_path.write_text(json.dumps(status, sort_keys=True), encoding="utf-8")
    _write_root_checksums(shards[0])

    with pytest.raises(ValueError, match=field):
        aggregate_day1_shards.aggregate_shards(
            shards_dir=download_dir,
            output_dir=tmp_path / "day1",
            experiment_plan=_fixture_plan_path(download_dir),
            manifest=MANIFEST_PATH,
            seed=SEED,
        )


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("microbatch_max_updates", 65),
        ("query_requires_latest", False),
        ("effective_slots", 2049),
        ("partition_rows", 129),
        ("layout_measurement_kind", "measured"),
    ],
)
def test_aggregator_binds_trace_header_to_manifest_and_plan(
    tmp_path: Path,
    field: str,
    invalid_value: object,
) -> None:
    download_dir = tmp_path / "downloaded-shards"
    shards = _build_download_layout(download_dir)
    cell_dir = next(path.parent for path in shards[0].rglob("event-window-trace.jsonl"))
    trace_path = cell_dir / "event-window-trace.jsonl"
    records = [json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines()]
    records[0][field] = invalid_value
    trace_path.write_bytes(_canonical_jsonl(records))
    _resign_cell_and_shard(shards[0], cell_dir)

    with pytest.raises(ValueError, match="deterministic generated stream"):
        aggregate_day1_shards.aggregate_shards(
            shards_dir=download_dir,
            output_dir=tmp_path / "day1",
            experiment_plan=_fixture_plan_path(download_dir),
            manifest=MANIFEST_PATH,
            seed=SEED,
        )


def test_aggregator_requires_exact_trace_header_keys(tmp_path: Path) -> None:
    download_dir = tmp_path / "downloaded-shards"
    shards = _build_download_layout(download_dir)
    cell_dir = next(path.parent for path in shards[0].rglob("event-window-trace.jsonl"))
    trace_path = cell_dir / "event-window-trace.jsonl"
    records = [json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines()]
    records[0]["unbound_claim"] = True
    trace_path.write_bytes(_canonical_jsonl(records))
    _resign_cell_and_shard(shards[0], cell_dir)

    with pytest.raises(ValueError, match="deterministic generated stream"):
        aggregate_day1_shards.aggregate_shards(
            shards_dir=download_dir,
            output_dir=tmp_path / "day1",
            experiment_plan=_fixture_plan_path(download_dir),
            manifest=MANIFEST_PATH,
            seed=SEED,
        )


@pytest.mark.parametrize(
    "mutation", ["skinny", "forged-score", "unknown-record", "unknown-candidate"]
)
def test_aggregator_reuses_report_validator_for_causal_payloads(
    tmp_path: Path,
    mutation: str,
) -> None:
    download_dir = tmp_path / "downloaded-shards"
    shards = _build_download_layout(download_dir)
    cell_dir = next(path.parent for path in shards[0].rglob("metrics.json"))
    metrics_path = cell_dir / "metrics.json"
    payload = json.loads(metrics_path.read_text(encoding="utf-8"))
    if mutation == "skinny":
        payload["unit_costs"] = {"label": "forged"}
    elif mutation == "forged-score":
        payload["tuning_aggregates"][0]["score"] += 1
    elif mutation == "unknown-record":
        payload["records"][0]["record_kind"] = "unknown"
    else:
        payload["records"][0]["candidate_id"] = "unknown-candidate"
    metrics_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    _resign_cell_and_shard(shards[0], cell_dir)

    with pytest.raises(ValueError, match="causal payload"):
        aggregate_day1_shards.aggregate_shards(
            shards_dir=download_dir,
            output_dir=tmp_path / "day1",
            experiment_plan=_fixture_plan_path(download_dir),
            manifest=MANIFEST_PATH,
            seed=SEED,
        )


def test_aggregator_requires_canonical_candidate_id_set_in_shard_status(
    tmp_path: Path,
) -> None:
    download_dir = tmp_path / "downloaded-shards"
    shards = _build_download_layout(download_dir)
    status_path = shards[0] / "SHARD_STATUS.json"
    status = json.loads(status_path.read_text(encoding="utf-8"))
    status["candidate_ids"] = list(reversed(status["candidate_ids"]))
    status_path.write_text(json.dumps(status, sort_keys=True), encoding="utf-8")
    _write_root_checksums(shards[0])

    with pytest.raises(ValueError, match="candidate_ids"):
        aggregate_day1_shards.aggregate_shards(
            shards_dir=download_dir,
            output_dir=tmp_path / "day1",
            experiment_plan=_fixture_plan_path(download_dir),
            manifest=MANIFEST_PATH,
            seed=SEED,
        )


@pytest.mark.parametrize("mutation", ["initial-digest", "query-total", "update-before"])
def test_aggregator_rejects_trace_content_that_is_not_bound_to_the_frozen_stream(
    tmp_path: Path,
    mutation: str,
) -> None:
    download_dir = tmp_path / "downloaded-shards"
    shards = _build_download_layout(download_dir)
    cell_dir = next(path.parent for path in shards[0].rglob("event-window-trace.jsonl"))
    trace_path = cell_dir / "event-window-trace.jsonl"
    records = [json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines()]
    if mutation == "initial-digest":
        records[0]["initial_state_sha256"] = "b" * 64
    elif mutation == "query-total":
        records[1]["query_count"] += 1
    else:
        records[1]["updates"] = [{"row": 0, "col": 0, "before": 99, "after": 1}]
    trace_path.write_bytes(_canonical_jsonl(records))
    _resign_cell_and_shard(shards[0], cell_dir)

    with pytest.raises(
        ValueError,
        match="initial_state_sha256|deterministic generated stream|before value",
    ):
        aggregate_day1_shards.aggregate_shards(
            shards_dir=download_dir,
            output_dir=tmp_path / "day1",
            experiment_plan=_fixture_plan_path(download_dir),
            manifest=MANIFEST_PATH,
            seed=SEED,
        )


@pytest.mark.parametrize("mutation", ["wrong-total", "extra-key"])
def test_aggregator_requires_exact_trace_derived_metrics_metadata(
    tmp_path: Path,
    mutation: str,
) -> None:
    download_dir = tmp_path / "downloaded-shards"
    shards = _build_download_layout(download_dir)
    cell_dir = next(path.parent for path in shards[0].rglob("metrics.json"))
    metrics_path = cell_dir / "metrics.json"
    payload = json.loads(metrics_path.read_text(encoding="utf-8"))
    if mutation == "wrong-total":
        payload["metadata"]["queries_total"] += 1
    else:
        payload["metadata"]["unbound_claim"] = True
    metrics_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    _resign_cell_and_shard(shards[0], cell_dir)

    with pytest.raises(ValueError, match="metadata"):
        aggregate_day1_shards.aggregate_shards(
            shards_dir=download_dir,
            output_dir=tmp_path / "day1",
            experiment_plan=_fixture_plan_path(download_dir),
            manifest=MANIFEST_PATH,
            seed=SEED,
        )


def test_aggregator_rejects_invalid_per_candidate_span80_curve(tmp_path: Path) -> None:
    download_dir = tmp_path / "downloaded-shards"
    shards = _build_download_layout(download_dir)
    cell_dir = next(path.parent for path in shards[0].rglob("metrics.json"))
    metrics_path = cell_dir / "metrics.json"
    payload = json.loads(metrics_path.read_text(encoding="utf-8"))
    candidate_id = next(iter(payload["metadata"]["span80_by_candidate"]))
    payload["metadata"]["span80_by_candidate"][candidate_id]["8"] = 2.0
    metrics_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    _resign_cell_and_shard(shards[0], cell_dir)

    with pytest.raises(ValueError, match="Span80"):
        aggregate_day1_shards.aggregate_shards(
            shards_dir=download_dir,
            output_dir=tmp_path / "day1",
            experiment_plan=_fixture_plan_path(download_dir),
            manifest=MANIFEST_PATH,
            seed=SEED,
        )


@pytest.mark.parametrize("location", ["shard", "cell"])
def test_aggregator_rejects_extra_status_keys(tmp_path: Path, location: str) -> None:
    download_dir = tmp_path / "downloaded-shards"
    shards = _build_download_layout(download_dir)
    status_path = shards[0] / "SHARD_STATUS.json"
    status = json.loads(status_path.read_text(encoding="utf-8"))
    target = status if location == "shard" else status["cells"][0]
    target["unbound_claim"] = True
    status_path.write_text(json.dumps(status, sort_keys=True), encoding="utf-8")
    _write_root_checksums(shards[0])

    with pytest.raises(ValueError, match="keys must be exact"):
        aggregate_day1_shards.aggregate_shards(
            shards_dir=download_dir,
            output_dir=tmp_path / "day1",
            experiment_plan=_fixture_plan_path(download_dir),
            manifest=MANIFEST_PATH,
            seed=SEED,
        )


def test_aggregator_rejects_a_canonical_trace_that_diverges_from_the_generated_stream(
    tmp_path: Path,
) -> None:
    download_dir = tmp_path / "downloaded-shards"
    shards = _build_download_layout(download_dir)
    cell_dir = next(path.parent for path in shards[0].rglob("event-window-trace.jsonl"))
    trace_path = cell_dir / "event-window-trace.jsonl"
    records = [json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines()]
    assert any(record["updates"] for record in records[1:])
    for record in records[1:]:
        record["updates"] = []
    trace_path.write_bytes(_canonical_jsonl(records))
    _resign_cell_and_shard(shards[0], cell_dir)

    with pytest.raises(ValueError, match="deterministic generated stream"):
        aggregate_day1_shards.aggregate_shards(
            shards_dir=download_dir,
            output_dir=tmp_path / "day1",
            experiment_plan=_fixture_plan_path(download_dir),
            manifest=MANIFEST_PATH,
            seed=SEED,
        )


@pytest.mark.parametrize(
    ("phase", "metric_field"),
    [
        ("held-out", "windows"),
        ("held-out", "queries"),
        ("tuning", "windows"),
        ("tuning", "queries"),
    ],
)
def test_aggregator_binds_report_window_and_query_counts_to_reconstructed_phases(
    tmp_path: Path,
    phase: str,
    metric_field: str,
) -> None:
    download_dir = tmp_path / "downloaded-shards"
    shards = _build_download_layout(download_dir)
    cell_dir = next(path.parent for path in shards[0].rglob("metrics.json"))
    metrics_path = cell_dir / "metrics.json"
    payload = json.loads(metrics_path.read_text(encoding="utf-8"))
    if phase == "held-out":
        fixed_records = [
            record for record in payload["records"] if record["record_kind"] == "fixed-candidate"
        ]
        fixed_records[1][metric_field] += 1
    else:
        payload["tuning_aggregates"][0]["metrics"][metric_field] += 1
    metrics_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    _resign_cell_and_shard(shards[0], cell_dir)

    with pytest.raises(ValueError, match=f"{phase}.*{metric_field}"):
        aggregate_day1_shards.aggregate_shards(
            shards_dir=download_dir,
            output_dir=tmp_path / "day1",
            experiment_plan=_fixture_plan_path(download_dir),
            manifest=MANIFEST_PATH,
            seed=SEED,
        )


@pytest.mark.parametrize(
    "field",
    [
        "events_planned",
        "update_events_total",
        "windows_total",
        "warmup_windows",
        "tuning_windows",
        "held_out_windows",
    ],
)
def test_aggregator_binds_metadata_counts_to_plan_stream_and_split(
    tmp_path: Path,
    field: str,
) -> None:
    download_dir = tmp_path / "downloaded-shards"
    shards = _build_download_layout(download_dir)
    cell_dir = next(path.parent for path in shards[0].rglob("metrics.json"))
    metrics_path = cell_dir / "metrics.json"
    payload = json.loads(metrics_path.read_text(encoding="utf-8"))
    payload["metadata"][field] += 1
    metrics_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    _resign_cell_and_shard(shards[0], cell_dir)

    with pytest.raises(ValueError, match=field):
        aggregate_day1_shards.aggregate_shards(
            shards_dir=download_dir,
            output_dir=tmp_path / "day1",
            experiment_plan=_fixture_plan_path(download_dir),
            manifest=MANIFEST_PATH,
            seed=SEED,
        )
