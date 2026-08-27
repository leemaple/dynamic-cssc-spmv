#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from collections.abc import Mapping
from dataclasses import fields
from fractions import Fraction
from pathlib import Path

from dynamic_cssc.day1_registry import repository_day1_candidate_catalog
from dynamic_cssc.events import Event, EventKind, PublicationWindow, publication_windows
from dynamic_cssc.manifest import load_manifest
from dynamic_cssc.metrics import StrategyMetrics, UnitCosts
from dynamic_cssc.report import (
    CAUSAL_ARTIFACT_FILENAMES,
    CAUSAL_MEASUREMENT_KIND,
    CAUSAL_SCHEMA,
    CAUSAL_STATE_MODEL,
    render_causal_artifacts,
    validate_causal_payload,
)
from dynamic_cssc.simulator import RotationInventory, SimulationConfig
from dynamic_cssc.workloads import generate_event_stream, generate_initial_matrix

if __package__:
    from .run_day1_suite import (
        EVENT_WINDOW_TRACE_SCHEMA,
        CausalCellResult,
        ExperimentPlan,
        _candidate_span80,
        _causal_evaluation_provenance,
        _initial_state_sha256,
        _query_scaled_windows,
        _rescale_causal_cell_queries,
        evaluate_causal_cell,
        freshness_path_id,
        insert_queries_by_ratio,
        load_experiment_plan,
        parse_canonical_seed,
        rho_path_id,
        write_checksums,
        write_event_window_trace,
    )
else:
    from run_day1_suite import (  # type: ignore[import-not-found]
        EVENT_WINDOW_TRACE_SCHEMA,
        CausalCellResult,
        ExperimentPlan,
        _candidate_span80,
        _causal_evaluation_provenance,
        _initial_state_sha256,
        _query_scaled_windows,
        _rescale_causal_cell_queries,
        evaluate_causal_cell,
        freshness_path_id,
        insert_queries_by_ratio,
        load_experiment_plan,
        parse_canonical_seed,
        rho_path_id,
        write_checksums,
        write_event_window_trace,
    )

REPLAY_RECEIPT_SCHEMA = "day1-shard-replay-receipt-v1"
VALIDATOR_SCHEMA = "day1-separate-deterministic-replay-validator-v3"
VALIDATOR_VERSION = "3"
REPLAY_RECEIPT_FILENAME = "REPLAY_RECEIPT.json"
DERIVED_ARTIFACT_FILENAMES = (
    "SUMMARY.md",
    "metrics.csv",
    "tuning_aggregates.csv",
    "t_rho_proxy.png",
    "ua_vs_qa_proxy.png",
)
_SOURCE_SHA_RE = re.compile(r"[0-9a-f]{40}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_RECEIPT_KEYS = frozenset(
    {
        "schema",
        "validator_schema",
        "validator_version",
        "validator_source_sha256",
        "source_git_sha",
        "experiment_plan_sha256",
        "manifest_sha256",
        "seed",
        "workload",
        "freshness_seconds_fraction",
        "freshness_id",
        "rho_ids",
        "cells_expected",
        "cells_replayed",
        "verified",
        "cells",
    }
)
_RECEIPT_CELL_KEYS = frozenset(
    {
        "relative_path",
        "rho_id",
        "rho_fraction",
        "event_window_trace_sha256",
        "metrics_json_sha256",
        "derived_artifact_sha256",
    }
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _mapping(value: object, field: str) -> dict[str, object]:
    if type(value) is not dict:
        raise ValueError(f"{field} must be an exact object")
    return value


def _list(value: object, field: str) -> list[object]:
    if type(value) is not list:
        raise ValueError(f"{field} must be an exact array")
    return value


def _exact_keys(value: Mapping[str, object], expected: frozenset[str], field: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ValueError(
            f"{field} keys must be exact; missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )


def _exact_value(actual: object, expected: object, field: str) -> None:
    if type(actual) is not type(expected) or actual != expected:
        raise ValueError(f"{field} does not match separate deterministic replay")


def _load_json(path: Path, field: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{field} is not readable JSON: {path}") from error
    return _mapping(value, field)


def _strict_fraction(value: object, field: str) -> Fraction:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an exact fraction")
    try:
        return Fraction(str(value))
    except (ValueError, ZeroDivisionError) as error:
        raise ValueError(f"{field} must be an exact fraction") from error


def _validator_source_sha256() -> str:
    return _sha256(Path(__file__).resolve())


def _base_config(plan: ExperimentPlan, manifest: Mapping[str, object]) -> SimulationConfig:
    integer_correctness = _mapping(
        manifest.get("integer_correctness"), "manifest.integer_correctness"
    )
    matrix = _mapping(manifest.get("matrix"), "manifest.matrix")
    matrix_entry_abs_bound = integer_correctness.get("matrix_entry_abs_bound")
    max_row_nnz = matrix.get("max_nnz_per_row")
    if (
        isinstance(matrix_entry_abs_bound, bool)
        or not isinstance(matrix_entry_abs_bound, int)
        or matrix_entry_abs_bound <= 0
    ):
        raise ValueError("manifest.integer_correctness.matrix_entry_abs_bound is invalid")
    if isinstance(max_row_nnz, bool) or not isinstance(max_row_nnz, int) or max_row_nnz <= 0:
        raise ValueError("manifest.matrix.max_nnz_per_row is invalid")
    return SimulationConfig(
        rows=plan.rows,
        cols=plan.cols,
        effective_slots=plan.effective_slots,
        partition_rows=plan.partition_rows,
        matrix_value_bound=matrix_entry_abs_bound,
        max_row_nnz=max_row_nnz,
        reserved_slack_beta=0.1,
        periodic_repack_windows=4,
        packed_coo_segment_capacity=128,
    )


def _assert_metrics(
    serialized: Mapping[str, object],
    expected: StrategyMetrics,
    field: str,
) -> None:
    for metric_field in fields(StrategyMetrics):
        name = metric_field.name
        _exact_value(serialized.get(name), getattr(expected, name), f"{field}.{name}")


def _assert_rotation_inventory(
    serialized: Mapping[str, object],
    expected: RotationInventory,
    field: str,
) -> None:
    _exact_value(
        serialized.get("rotation_inventory"),
        {
            "measured_counts_by_exact_index": [
                [index, count] for index, count in expected.measured_counts_by_exact_index
            ],
            "required_indices": list(expected.required_indices),
        },
        f"{field}.rotation_inventory",
    )


def _expected_metadata(
    *,
    plan: ExperimentPlan,
    plan_sha256: str,
    manifest_sha256: str,
    seed: int,
    workload: str,
    workload_seed: int,
    freshness: Fraction,
    ratio: Fraction,
    initial_state_sha256: str,
    trace_sha256: str,
    windows: list[PublicationWindow],
    events: list[Event],
    result: CausalCellResult,
    causal_evaluation_mode: str,
    query_scaling_source_rho_fraction: str | None,
) -> dict[str, object]:
    update_events_total = sum(event.kind == EventKind.SET for event in events)
    queries_total = sum(event.kind == EventKind.QUERY for event in events)
    held_out = windows[result.tuning_end :]
    return {
        "workload": workload,
        "seed": workload_seed,
        "suite_seed": seed,
        "rows": plan.rows,
        "cols": plan.cols,
        "initial_nnz_per_row": plan.initial_nnz_per_row,
        "events_planned": plan.events,
        "effective_slots": plan.effective_slots,
        "partition_rows": plan.partition_rows,
        "layout_measurement_kind": plan.layout_measurement_kind,
        "freshness_seconds": float(freshness),
        "freshness_seconds_fraction": str(freshness),
        "queries_per_update_target": float(ratio),
        "queries_per_update_fraction": str(ratio),
        "rho_id": rho_path_id(ratio),
        "causal_evaluation_mode": causal_evaluation_mode,
        "query_scaling_source_rho_fraction": query_scaling_source_rho_fraction,
        "queries_per_update_scheduled": (
            queries_total / update_events_total if update_events_total else 0.0
        ),
        "update_events_total": update_events_total,
        "queries_total": queries_total,
        "held_out_queries": sum(window.query_count for window in held_out),
        "windows_total": len(windows),
        "warmup_windows": result.warmup_end,
        "tuning_windows": result.tuning_end - result.warmup_end,
        "held_out_windows": len(held_out),
        "fixed_candidate_count": len(result.fixed_results),
        "reference_candidate_count": len(result.tuning_results),
        "ablation_candidate_count": len(result.fixed_results) - len(result.tuning_results),
        "selected_candidate_id": result.selected_candidate_id,
        "oracle_candidate_id": result.oracle_candidate_id,
        "span80_by_candidate": _candidate_span80(plan.rows, result),
        "experiment_plan_sha256": plan_sha256,
        "manifest_sha256": manifest_sha256,
        "initial_state_sha256": initial_state_sha256,
        "event_window_trace_schema": EVENT_WINDOW_TRACE_SCHEMA,
        "event_window_trace_sha256": trace_sha256,
        "real_temporal_dataset": False,
        "state_model": "persistent-strategy-snapshots",
        "measurement_kind": "predicted-proxy",
        "gate_eligible": False,
        "complete_cost_claim_allowed": False,
        "security_claim_allowed": False,
        "formal_performance_claim": False,
        "complete_reference_set": True,
    }


def _replay_cell(
    *,
    cell_dir: Path,
    plan: ExperimentPlan,
    plan_sha256: str,
    manifest_payload: Mapping[str, object],
    manifest_sha256: str,
    seed: int,
    workload: str,
    freshness: Fraction,
    ratio: Fraction,
    initial_state: dict[tuple[int, int], int],
    initial_state_sha256: str,
    causal_evaluation_mode: str,
    query_scaling_source_rho_fraction: str | None,
    query_scaling_source_windows: list[PublicationWindow] | None,
    query_scaling_source_result: CausalCellResult | None,
) -> tuple[dict[str, object], list[PublicationWindow], CausalCellResult]:
    integer_correctness = _mapping(
        manifest_payload.get("integer_correctness"), "manifest.integer_correctness"
    )
    freshness_contract = _mapping(manifest_payload.get("freshness"), "manifest.freshness")
    matrix_entry_abs_bound = integer_correctness.get("matrix_entry_abs_bound")
    microbatch_max_updates = freshness_contract.get("microbatch_max_updates")
    query_requires_latest = freshness_contract.get("query_requires_latest")
    if isinstance(matrix_entry_abs_bound, bool) or not isinstance(matrix_entry_abs_bound, int):
        raise ValueError("manifest matrix_entry_abs_bound must be a strict integer")
    if isinstance(microbatch_max_updates, bool) or not isinstance(microbatch_max_updates, int):
        raise ValueError("manifest microbatch_max_updates must be a strict integer")
    if type(query_requires_latest) is not bool:
        raise ValueError("manifest query_requires_latest must be an exact bool")

    workload_seed = seed + plan.workloads.index(workload) + 1
    base_events = generate_event_stream(
        workload,
        initial_state,
        rows=plan.rows,
        cols=plan.cols,
        update_count=plan.events,
        seed=workload_seed,
        query_every=0,
        matrix_entry_abs_bound=matrix_entry_abs_bound,
    )
    events = insert_queries_by_ratio(base_events, ratio)
    windows = list(
        publication_windows(
            events,
            initial_state,
            max_seconds=float(freshness),
            microbatch_max_updates=microbatch_max_updates,
            query_requires_latest=query_requires_latest,
        )
    )
    with tempfile.TemporaryDirectory(prefix="day1-trace-replay-") as temporary:
        expected_trace = Path(temporary) / "event-window-trace.jsonl"
        expected_trace_sha256 = write_event_window_trace(
            expected_trace,
            windows=windows,
            workload=workload,
            freshness_seconds=freshness,
            ratio=ratio,
            experiment_plan_sha256=plan_sha256,
            manifest_sha256=manifest_sha256,
            seed=seed,
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
        actual_trace = cell_dir / "event-window-trace.jsonl"
        if actual_trace.read_bytes() != expected_trace.read_bytes():
            raise ValueError(f"event-window trace does not match deterministic replay: {cell_dir}")

    costs = UnitCosts()
    if query_scaling_source_rho_fraction is None:
        result = evaluate_causal_cell(
            windows=windows,
            initial_state=initial_state,
            base_config=_base_config(plan, manifest_payload),
            split=plan.split,
            costs=costs,
        )
    else:
        if query_scaling_source_rho_fraction != "1":
            raise ValueError("query scaling replay source must be exactly rho=1")
        if query_scaling_source_windows is None or query_scaling_source_result is None:
            raise ValueError("query scaling replay requires the independently replayed rho=1 cell")
        if ratio.denominator != 1 or ratio <= 1:
            raise ValueError("query scaling replay target must be an integer rho greater than one")
        multiplier = ratio.numerator
        if not _query_scaled_windows(
            query_scaling_source_windows,
            windows,
            multiplier,
        ):
            raise ValueError(
                "integer-rho replay scaling requires an exact rho=1 window trajectory"
            )
        result = _rescale_causal_cell_queries(
            query_scaling_source_result,
            multiplier,
            costs,
        )
    metrics_path = cell_dir / "metrics.json"
    payload = _load_json(metrics_path, "metrics.json")
    candidate_ids = tuple(sorted(result.fixed_results))
    tuning_candidate_ids = tuple(sorted(result.tuning_results))
    if len(candidate_ids) != 14 or len(tuning_candidate_ids) != 13:
        raise ValueError(
            "separate deterministic replay did not produce the canonical 14/13 candidate roles"
        )
    if not set(tuning_candidate_ids).issubset(candidate_ids):
        raise ValueError(
            "separate deterministic replay tuning references are not held-out fixed candidates"
        )
    try:
        validate_causal_payload(payload)
    except (TypeError, ValueError) as error:
        raise ValueError(
            f"metrics.json fails canonical causal validation: {cell_dir}: {error}"
        ) from error

    tuning = _list(payload.get("tuning_aggregates"), "metrics.json.tuning_aggregates")
    tuning_by_id = {
        _mapping(item, "metrics.json tuning aggregate")["candidate_id"]: _mapping(
            _mapping(item, "metrics.json tuning aggregate").get("metrics"),
            "metrics.json tuning metrics",
        )
        for item in tuning
    }
    records = _list(payload.get("records"), "metrics.json.records")
    fixed_by_id: dict[object, dict[str, object]] = {}
    aliases: dict[object, dict[str, object]] = {}
    for item in records:
        record = _mapping(item, "metrics.json record")
        if record.get("record_kind") == "fixed-candidate":
            fixed_by_id[record.get("candidate_id")] = record
        else:
            aliases[record.get("record_kind")] = record
    for candidate_id in tuning_candidate_ids:
        _assert_metrics(
            tuning_by_id[candidate_id],
            result.tuning_results[candidate_id].metrics,
            f"tuning replay metrics {candidate_id}",
        )
    for candidate_id in candidate_ids:
        _assert_metrics(
            fixed_by_id[candidate_id],
            result.fixed_results[candidate_id].metrics,
            f"held-out replay metrics {candidate_id}",
        )
        _assert_rotation_inventory(
            fixed_by_id[candidate_id],
            result.fixed_results[candidate_id].rotation_inventory,
            f"held-out replay metrics {candidate_id}",
        )
    _assert_metrics(
        aliases["tuned-fixed-policy"],
        result.tuned_policy,
        "tuned-fixed-policy replay alias",
    )
    _assert_metrics(
        aliases["diagnostic-oracle"],
        result.offline_oracle,
        "diagnostic-oracle replay alias",
    )
    _assert_rotation_inventory(
        aliases["tuned-fixed-policy"],
        result.fixed_results[result.selected_candidate_id].rotation_inventory,
        "tuned-fixed-policy replay alias",
    )
    _assert_rotation_inventory(
        aliases["diagnostic-oracle"],
        result.fixed_results[result.oracle_candidate_id].rotation_inventory,
        "diagnostic-oracle replay alias",
    )
    _exact_value(
        aliases["tuned-fixed-policy"].get("candidate_id"),
        result.selected_candidate_id,
        "tuned-fixed-policy candidate_id",
    )
    _exact_value(
        aliases["diagnostic-oracle"].get("candidate_id"),
        result.oracle_candidate_id,
        "diagnostic-oracle candidate_id",
    )

    metadata = _mapping(payload.get("metadata"), "metrics.json.metadata")
    expected_metadata = _expected_metadata(
        plan=plan,
        plan_sha256=plan_sha256,
        manifest_sha256=manifest_sha256,
        seed=seed,
        workload=workload,
        workload_seed=workload_seed,
        freshness=freshness,
        ratio=ratio,
        initial_state_sha256=initial_state_sha256,
        trace_sha256=expected_trace_sha256,
        windows=windows,
        events=events,
        result=result,
        causal_evaluation_mode=causal_evaluation_mode,
        query_scaling_source_rho_fraction=query_scaling_source_rho_fraction,
    )
    if set(metadata) != set(expected_metadata):
        raise ValueError(
            f"metrics.json metadata keys do not match separate deterministic replay: {cell_dir}"
        )
    for name, expected in expected_metadata.items():
        actual = metadata.get(name)
        if name == "span80_by_candidate":
            expected = json.loads(json.dumps(expected, allow_nan=False))
        _exact_value(actual, expected, f"metrics.json metadata.{name}")

    with tempfile.TemporaryDirectory(prefix="day1-report-replay-") as temporary:
        rendered_dir = Path(temporary)
        rendered_digests = render_causal_artifacts(
            rendered_dir,
            payload,
        )
        if tuple(rendered_digests) != CAUSAL_ARTIFACT_FILENAMES:
            raise ValueError("canonical renderer returned an unexpected artifact set")
        for filename in CAUSAL_ARTIFACT_FILENAMES:
            actual_path = cell_dir / filename
            rendered_path = rendered_dir / filename
            if actual_path.read_bytes() != rendered_path.read_bytes():
                raise ValueError(
                    f"derived artifact does not match canonical metrics rendering: "
                    f"{cell_dir}/{filename}"
                )
        derived_digests = {
            filename: rendered_digests[filename] for filename in DERIVED_ARTIFACT_FILENAMES
        }

    return (
        {
            "relative_path": cell_dir.as_posix(),
            "rho_id": rho_path_id(ratio),
            "rho_fraction": str(ratio),
            "event_window_trace_sha256": expected_trace_sha256,
            "metrics_json_sha256": _sha256(metrics_path),
            "derived_artifact_sha256": derived_digests,
        },
        windows,
        result,
    )


def _canonical_receipt_bytes(receipt: Mapping[str, object]) -> bytes:
    return (
        json.dumps(receipt, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode("utf-8")


def replay_shard(
    *,
    shard_dir: Path,
    experiment_plan: Path,
    manifest: Path,
    seed: int,
    workload: str,
    freshness: Fraction,
    source_sha: str,
) -> dict[str, object]:
    """Replay one complete shard from frozen sources and atomically issue its receipt."""

    receipt_path = shard_dir / REPLAY_RECEIPT_FILENAME
    receipt_path.unlink(missing_ok=True)
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be a strict integer")
    if _SOURCE_SHA_RE.fullmatch(source_sha) is None:
        raise ValueError("source_sha must be an exact lowercase 40-hex commit SHA")
    plan = load_experiment_plan(experiment_plan)
    if workload not in plan.workloads:
        raise ValueError("workload is not in the experiment plan")
    if freshness not in plan.freshness_seconds:
        raise ValueError("freshness is not in the experiment plan")
    if len(plan.ratio_grid) != 9:
        raise ValueError("a replayable Day-1 shard must contain exactly nine rho cells")
    manifest_payload = load_manifest(manifest)
    candidate_catalog = repository_day1_candidate_catalog()
    fixed_candidate_ids = sorted(
        candidate.candidate_id for candidate in candidate_catalog.candidates
    )
    reference_candidate_ids = sorted(
        candidate.candidate_id for candidate in candidate_catalog.selection_candidates
    )
    ablation_candidate_ids = sorted(
        candidate.candidate_id for candidate in candidate_catalog.ablation_candidates
    )
    plan_sha256 = _sha256(experiment_plan)
    manifest_sha256 = _sha256(manifest)
    status = _load_json(shard_dir / "SHARD_STATUS.json", "SHARD_STATUS")
    for field, expected in (
        ("seed", seed),
        ("workload", workload),
        ("freshness_seconds_fraction", str(freshness)),
        ("experiment_plan_sha256", plan_sha256),
        ("manifest_sha256", manifest_sha256),
        ("schema", CAUSAL_SCHEMA),
        ("state_model", CAUSAL_STATE_MODEL),
        ("measurement_kind", CAUSAL_MEASUREMENT_KIND),
        ("gate_eligible", False),
        ("complete_cost_claim_allowed", False),
        ("security_claim_allowed", False),
        ("formal_performance_claim", False),
        ("complete_reference_set", True),
        ("suite_complete", False),
        ("deferred_reference_baselines", []),
        ("candidate_ids", fixed_candidate_ids),
        ("reference_candidate_ids", reference_candidate_ids),
        ("ablation_candidate_ids", ablation_candidate_ids),
        ("fixed_candidate_count", 14),
        ("reference_candidate_count", 13),
        ("ablation_candidate_count", 1),
        ("cells_expected", 9),
        ("cells_completed", 9),
    ):
        _exact_value(status.get(field), expected, f"SHARD_STATUS.{field}")
    expected_rho_ids = [rho_path_id(ratio) for ratio in plan.ratio_grid]
    _exact_value(status.get("rho_ids"), expected_rho_ids, "SHARD_STATUS.rho_ids")

    base_config = _base_config(plan, manifest_payload)
    initial_state = generate_initial_matrix(
        plan.rows,
        plan.cols,
        plan.initial_nnz_per_row,
        seed=seed,
        matrix_entry_abs_bound=base_config.matrix_value_bound,
    )
    initial_state_sha256 = _initial_state_sha256(initial_state)
    freshness_id = freshness_path_id(freshness)
    cells: list[dict[str, object]] = []
    rho_one_available = False
    unit_ratio_windows: list[PublicationWindow] | None = None
    unit_ratio_result: CausalCellResult | None = None
    for ratio in plan.ratio_grid:
        causal_evaluation_mode, query_scaling_source_rho_fraction = (
            _causal_evaluation_provenance(
                ratio,
                rho_one_available=rho_one_available,
            )
        )
        relative_path = Path(workload) / freshness_id / rho_path_id(ratio)
        cell, replayed_windows, replayed_result = _replay_cell(
            cell_dir=shard_dir / relative_path,
            plan=plan,
            plan_sha256=plan_sha256,
            manifest_payload=manifest_payload,
            manifest_sha256=manifest_sha256,
            seed=seed,
            workload=workload,
            freshness=freshness,
            ratio=ratio,
            initial_state=initial_state,
            initial_state_sha256=initial_state_sha256,
            causal_evaluation_mode=causal_evaluation_mode,
            query_scaling_source_rho_fraction=query_scaling_source_rho_fraction,
            query_scaling_source_windows=unit_ratio_windows,
            query_scaling_source_result=unit_ratio_result,
        )
        cell["relative_path"] = relative_path.as_posix()
        cells.append(cell)
        if ratio == 1:
            rho_one_available = True
            unit_ratio_windows = replayed_windows
            unit_ratio_result = replayed_result

    receipt: dict[str, object] = {
        "schema": REPLAY_RECEIPT_SCHEMA,
        "validator_schema": VALIDATOR_SCHEMA,
        "validator_version": VALIDATOR_VERSION,
        "validator_source_sha256": _validator_source_sha256(),
        "source_git_sha": source_sha,
        "experiment_plan_sha256": plan_sha256,
        "manifest_sha256": manifest_sha256,
        "seed": seed,
        "workload": workload,
        "freshness_seconds_fraction": str(freshness),
        "freshness_id": freshness_id,
        "rho_ids": expected_rho_ids,
        "cells_expected": 9,
        "cells_replayed": len(cells),
        "verified": True,
        "cells": cells,
    }
    temporary_path = receipt_path.with_name(f".{receipt_path.name}.{os.getpid()}.tmp")
    try:
        temporary_path.write_bytes(_canonical_receipt_bytes(receipt))
        temporary_path.replace(receipt_path)
    finally:
        temporary_path.unlink(missing_ok=True)
    write_checksums(shard_dir)
    return receipt


def validate_replay_receipt(
    receipt_path: Path,
    *,
    shard_dir: Path,
    plan: ExperimentPlan,
    experiment_plan_sha256: str,
    manifest_sha256: str,
    seed: int,
    workload: str,
    freshness: Fraction,
    expected_source_sha: str,
) -> dict[str, object]:
    """Validate an immutable replay receipt and every digest it binds."""

    raw = receipt_path.read_bytes()
    receipt = _load_json(receipt_path, "replay receipt")
    if raw != _canonical_receipt_bytes(receipt):
        raise ValueError(f"replay receipt must be canonical JSON with one newline: {receipt_path}")
    _exact_keys(receipt, _RECEIPT_KEYS, "replay receipt")
    for field, expected in (
        ("schema", REPLAY_RECEIPT_SCHEMA),
        ("validator_schema", VALIDATOR_SCHEMA),
        ("validator_version", VALIDATOR_VERSION),
        ("validator_source_sha256", _validator_source_sha256()),
        ("experiment_plan_sha256", experiment_plan_sha256),
        ("manifest_sha256", manifest_sha256),
        ("seed", seed),
        ("workload", workload),
        ("freshness_seconds_fraction", str(freshness)),
        ("freshness_id", freshness_path_id(freshness)),
        ("rho_ids", [rho_path_id(ratio) for ratio in plan.ratio_grid]),
        ("cells_expected", 9),
        ("cells_replayed", 9),
        ("verified", True),
    ):
        _exact_value(receipt.get(field), expected, f"replay receipt.{field}")
    if _SOURCE_SHA_RE.fullmatch(expected_source_sha) is None:
        raise ValueError("expected_source_sha must be an exact lowercase 40-hex commit SHA")
    _exact_value(
        receipt.get("source_git_sha"),
        expected_source_sha,
        "replay receipt.source_git_sha",
    )
    cells = _list(receipt.get("cells"), "replay receipt.cells")
    if len(cells) != 9:
        raise ValueError("replay receipt must bind exactly nine cells")
    for value, ratio in zip(cells, plan.ratio_grid, strict=True):
        cell = _mapping(value, "replay receipt cell")
        _exact_keys(cell, _RECEIPT_CELL_KEYS, "replay receipt cell")
        rho_id = rho_path_id(ratio)
        relative_path = (Path(workload) / freshness_path_id(freshness) / rho_id).as_posix()
        for field, expected in (
            ("relative_path", relative_path),
            ("rho_id", rho_id),
            ("rho_fraction", str(ratio)),
        ):
            _exact_value(cell.get(field), expected, f"replay receipt cell.{field}")
        cell_dir = shard_dir / relative_path
        for field, filename in (
            ("event_window_trace_sha256", "event-window-trace.jsonl"),
            ("metrics_json_sha256", "metrics.json"),
        ):
            digest = cell.get(field)
            if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
                raise ValueError(f"replay receipt cell.{field} must be exact SHA-256")
            _exact_value(digest, _sha256(cell_dir / filename), f"replay receipt cell.{field}")
        derived = _mapping(
            cell.get("derived_artifact_sha256"),
            "replay receipt cell.derived_artifact_sha256",
        )
        if set(derived) != set(DERIVED_ARTIFACT_FILENAMES):
            raise ValueError("replay receipt derived artifact map must bind the exact five files")
        for filename in DERIVED_ARTIFACT_FILENAMES:
            digest = derived.get(filename)
            if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
                raise ValueError(f"replay receipt derived digest is invalid for {filename}")
            _exact_value(
                digest,
                _sha256(cell_dir / filename),
                f"replay receipt derived digest {filename}",
            )
    return receipt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Independently replay one Day-1 shard and issue a digest-bound receipt"
    )
    parser.add_argument("--shard-dir", required=True, type=Path)
    parser.add_argument("--experiment-plan", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--seed", required=True, type=parse_canonical_seed)
    parser.add_argument("--workload", required=True)
    parser.add_argument("--freshness-seconds", required=True)
    parser.add_argument("--source-sha", required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    replay_shard(
        shard_dir=args.shard_dir,
        experiment_plan=args.experiment_plan,
        manifest=args.manifest,
        seed=args.seed,
        workload=args.workload,
        freshness=_strict_fraction(args.freshness_seconds, "--freshness-seconds"),
        source_sha=args.source_sha,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
