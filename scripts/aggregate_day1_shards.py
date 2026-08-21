#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import shutil
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from fractions import Fraction
from pathlib import Path

from dynamic_cssc.events import EventKind, publication_windows
from dynamic_cssc.manifest import load_manifest
from dynamic_cssc.preflight import run_day1_preflight
from dynamic_cssc.report import (
    CAUSAL_MEASUREMENT_KIND,
    CAUSAL_SCHEMA,
    CAUSAL_STATE_MODEL,
    validate_causal_payload,
)
from dynamic_cssc.selection import split_boundaries
from dynamic_cssc.workloads import generate_event_stream, generate_initial_matrix

if __package__:
    from .run_day1_suite import (
        DEFERRED_REFERENCE_BASELINES,
        EVENT_WINDOW_TRACE_SCHEMA,
        ExperimentPlan,
        freshness_path_id,
        insert_queries_by_ratio,
        load_experiment_plan,
        rho_path_id,
    )
else:
    from run_day1_suite import (  # type: ignore[import-not-found]
        DEFERRED_REFERENCE_BASELINES,
        EVENT_WINDOW_TRACE_SCHEMA,
        ExperimentPlan,
        freshness_path_id,
        insert_queries_by_ratio,
        load_experiment_plan,
        rho_path_id,
    )

R2_WORKLOAD_COUNT = 7
R2_FRESHNESS_COUNT = 3
R2_RHO_COUNT = 9
R2_SHARD_COUNT = R2_WORKLOAD_COUNT * R2_FRESHNESS_COUNT
R2_CELL_COUNT = R2_SHARD_COUNT * R2_RHO_COUNT
REQUIRED_CELL_FILES = frozenset(
    {
        "SUMMARY.md",
        "event-window-trace.jsonl",
        "metrics.csv",
        "metrics.json",
        "t_rho_proxy.png",
        "tuning_aggregates.csv",
        "ua_vs_qa_proxy.png",
    }
)
SHARD_STATUS_KEYS = frozenset(
    {
        "schema",
        "state_model",
        "measurement_kind",
        "gate_eligible",
        "complete_cost_claim_allowed",
        "complete_reference_set",
        "suite_complete",
        "deferred_reference_baselines",
        "seed",
        "experiment_plan_sha256",
        "manifest_sha256",
        "experiment_plan_version",
        "workload",
        "freshness_seconds",
        "freshness_seconds_fraction",
        "rho_ids",
        "cells_expected",
        "cells_completed",
        "candidate_ids",
        "effective_slots",
        "partition_rows",
        "layout_measurement_kind",
        "planned_bandwidth_profiles_mbps",
        "deferred_unpriced_plan_dimensions",
        "preflight",
        "cells",
    }
)
CELL_STATUS_KEYS = frozenset(
    {
        "relative_path",
        "rho_id",
        "rho_fraction",
        "event_window_trace_sha256",
        "cell_checksums_sha256",
    }
)
CELL_METADATA_KEYS = frozenset(
    {
        "workload",
        "seed",
        "suite_seed",
        "rows",
        "cols",
        "initial_nnz_per_row",
        "events_planned",
        "effective_slots",
        "partition_rows",
        "layout_measurement_kind",
        "freshness_seconds",
        "freshness_seconds_fraction",
        "queries_per_update_target",
        "queries_per_update_fraction",
        "rho_id",
        "queries_per_update_scheduled",
        "update_events_total",
        "queries_total",
        "held_out_queries",
        "windows_total",
        "warmup_windows",
        "tuning_windows",
        "held_out_windows",
        "fixed_candidate_count",
        "selected_candidate_id",
        "oracle_candidate_id",
        "span80_by_candidate",
        "experiment_plan_sha256",
        "manifest_sha256",
        "initial_state_sha256",
        "event_window_trace_schema",
        "event_window_trace_sha256",
        "real_temporal_dataset",
        "state_model",
        "measurement_kind",
        "gate_eligible",
        "complete_cost_claim_allowed",
        "complete_reference_set",
    }
)
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_EXPECTED_TRACE_CACHE_MAX_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class CellEvidence:
    source: Path
    cell_id: str
    trace_sha256: str
    initial_state_sha256: str


@dataclass(frozen=True, slots=True)
class ShardEvidence:
    artifact_name: str
    workload: str
    freshness: Fraction
    cells: tuple[CellEvidence, ...]


@dataclass(frozen=True, slots=True)
class TraceContract:
    initial_state: Mapping[tuple[int, int], int]
    initial_state_sha256: str
    microbatch_max_updates: int
    query_requires_latest: bool
    matrix_entry_abs_bound: int


@dataclass(frozen=True, slots=True)
class TraceEvidence:
    sha256: str
    initial_state_sha256: str
    window_count: int
    warmup_end: int
    tuning_end: int
    update_events_total: int
    queries_total: int
    tuning_queries: int
    held_out_queries: int


@dataclass(frozen=True, slots=True)
class ReconstructedTrace:
    canonical_jsonl: bytes
    window_count: int
    warmup_end: int
    tuning_end: int
    update_events_total: int
    queries_total: int
    tuning_queries: int
    held_out_queries: int


_EXPECTED_TRACE_CACHE: OrderedDict[tuple[str, str, int, str, str, str], ReconstructedTrace] = (
    OrderedDict()
)
_expected_trace_cache_bytes = 0


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    return value


def _require_exact_keys(value: Mapping[str, object], expected: frozenset[str], field: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ValueError(
            f"{field} keys must be exact; missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )


def _require_exact_json_value(actual: object, expected: object, field: str) -> None:
    if type(actual) is not type(expected):
        raise ValueError(f"{field} must have the exact frozen JSON type and value")
    if isinstance(expected, dict):
        if set(actual) != set(expected):  # type: ignore[arg-type]
            raise ValueError(f"{field} must have the exact frozen JSON keys")
        for key, expected_value in expected.items():
            _require_exact_json_value(actual[key], expected_value, f"{field}.{key}")  # type: ignore[index]
        return
    if isinstance(expected, list):
        if len(actual) != len(expected):  # type: ignore[arg-type]
            raise ValueError(f"{field} must have the exact frozen JSON array")
        for index, (actual_item, expected_item) in enumerate(
            zip(actual, expected, strict=True)  # type: ignore[arg-type]
        ):
            _require_exact_json_value(actual_item, expected_item, f"{field}[{index}]")
        return
    if actual != expected:
        raise ValueError(f"{field} must have the exact frozen JSON value")


def _list(value: object, field: str) -> list[object]:
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list")
    return value


def _exact_false(value: object, field: str) -> None:
    if type(value) is not bool or value is not False:
        raise ValueError(f"{field} must be the exact false claim flag")


def _strict_int(value: object, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{field} must be a strict integer >= {minimum}")
    return value


def _exact_fraction(value: object, field: str) -> Fraction:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an exact fraction")
    try:
        return Fraction(str(value))
    except (ValueError, ZeroDivisionError) as error:
        raise ValueError(f"{field} must be an exact fraction") from error


def _load_json(path: Path, field: str) -> Mapping[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{field} is not a readable JSON object: {path}") from error
    return _mapping(payload, field)


def _validate_plan_shape(plan: ExperimentPlan) -> None:
    shape = (len(plan.workloads), len(plan.freshness_seconds), len(plan.ratio_grid))
    if shape != (R2_WORKLOAD_COUNT, R2_FRESHNESS_COUNT, R2_RHO_COUNT):
        raise ValueError(
            "R2 experiment plan must have the exact 7 workload x 3 freshness x 9 rho shape"
        )


def _parse_checksum_manifest(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise ValueError(f"checksum manifest is unreadable: {path}") from error
    checksums: dict[str, str] = {}
    for line in lines:
        parts = line.split("  ", 1)
        if len(parts) != 2 or _SHA256_RE.fullmatch(parts[0]) is None:
            raise ValueError(f"malformed checksum entry in {path}")
        digest, relative = parts
        relative_path = Path(relative)
        if (
            not relative
            or relative_path.is_absolute()
            or ".." in relative_path.parts
            or relative in checksums
        ):
            raise ValueError(f"unsafe or duplicate checksum path in {path}: {relative}")
        checksums[relative] = digest
    return checksums


def _validate_checksum_targets(directory: Path, checksums: Mapping[str, str]) -> None:
    for relative, expected_digest in checksums.items():
        target = directory / relative
        if not target.is_file():
            raise ValueError(f"checksum target is missing: {target}")
        if _sha256(target) != expected_digest:
            raise ValueError(f"checksum mismatch for {target}")


def _validate_exact_shard_tree(shard_dir: Path, cells: tuple[CellEvidence, ...]) -> set[str]:
    expected_files = {"SHARD_STATUS.json", "SHA256SUMS"}
    expected_directories: set[str] = set()
    for cell in cells:
        cell_path = Path(cell.cell_id)
        expected_files.update(
            (cell_path / filename).as_posix()
            for filename in (*sorted(REQUIRED_CELL_FILES), "SHA256SUMS")
        )
        expected_directories.add(cell_path.as_posix())
        expected_directories.update(
            parent.as_posix() for parent in cell_path.parents if parent.parts
        )

    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    invalid_types: list[str] = []
    for path in shard_dir.rglob("*"):
        relative = path.relative_to(shard_dir).as_posix()
        if path.is_symlink():
            invalid_types.append(relative)
        elif path.is_file():
            actual_files.add(relative)
        elif path.is_dir():
            actual_directories.add(relative)
        else:
            invalid_types.append(relative)
    if invalid_types:
        raise ValueError(
            f"shard exact artifact tree requires regular files/directories without symlinks: "
            f"{shard_dir}; invalid={sorted(invalid_types)}"
        )
    if actual_files != expected_files or actual_directories != expected_directories:
        raise ValueError(
            f"shard must contain the exact artifact tree: {shard_dir}; "
            f"missing_files={sorted(expected_files - actual_files)}, "
            f"extra_files={sorted(actual_files - expected_files)}, "
            f"missing_directories={sorted(expected_directories - actual_directories)}, "
            f"extra_directories={sorted(actual_directories - expected_directories)}"
        )
    return expected_files - {
        "SHA256SUMS",
        *(f"{cell.cell_id}/SHA256SUMS" for cell in cells),
    }


def _canonical_json_line(payload: Mapping[str, object]) -> bytes:
    return (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode("utf-8")


def _initial_state_sha256(initial_state: Mapping[tuple[int, int], int]) -> str:
    entries = [
        {"row": row, "col": col, "value": value}
        for (row, col), value in sorted(initial_state.items())
    ]
    canonical = json.dumps(
        entries,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _reconstruct_trace(
    *,
    plan: ExperimentPlan,
    plan_sha256: str,
    manifest_sha256: str,
    seed: int,
    workload: str,
    freshness: Fraction,
    ratio: Fraction,
    contract: TraceContract,
) -> ReconstructedTrace:
    global _expected_trace_cache_bytes

    cache_key = (
        plan_sha256,
        manifest_sha256,
        seed,
        workload,
        str(freshness),
        str(ratio),
    )
    cached = _EXPECTED_TRACE_CACHE.get(cache_key)
    if cached is not None:
        _EXPECTED_TRACE_CACHE.move_to_end(cache_key)
        return cached

    workload_seed = seed + plan.workloads.index(workload) + 1
    base_events = generate_event_stream(
        workload,
        dict(contract.initial_state),
        rows=plan.rows,
        cols=plan.cols,
        update_count=plan.events,
        seed=workload_seed,
        query_every=0,
        matrix_entry_abs_bound=contract.matrix_entry_abs_bound,
    )
    events = insert_queries_by_ratio(base_events, ratio)
    windows = list(
        publication_windows(
            events,
            dict(contract.initial_state),
            max_seconds=float(freshness),
            microbatch_max_updates=contract.microbatch_max_updates,
            query_requires_latest=contract.query_requires_latest,
        )
    )
    try:
        warmup_end, tuning_end = split_boundaries(len(windows), plan.split)
    except ValueError as error:
        raise ValueError(
            f"deterministic generated stream has empty phases for {workload}/{freshness}/{ratio}"
        ) from error

    header: dict[str, object] = {
        "record_type": "header",
        "schema": EVENT_WINDOW_TRACE_SCHEMA,
        "cell": {
            "workload": workload,
            "freshness_seconds_fraction": str(freshness),
            "rho_fraction": str(ratio),
            "rho_id": rho_path_id(ratio),
        },
        "experiment_plan_sha256": plan_sha256,
        "manifest_sha256": manifest_sha256,
        "seed": seed,
        "workload_seed": workload_seed,
        "matrix": {
            "rows": plan.rows,
            "cols": plan.cols,
            "initial_nnz_per_row": plan.initial_nnz_per_row,
        },
        "effective_slots": plan.effective_slots,
        "partition_rows": plan.partition_rows,
        "layout_measurement_kind": plan.layout_measurement_kind,
        "initial_state_sha256": contract.initial_state_sha256,
        "initial_state_digest_algorithm": "sha256-canonical-json-v1",
        "microbatch_max_updates": contract.microbatch_max_updates,
        "query_requires_latest": contract.query_requires_latest,
        "split": {
            "warmup": str(plan.split[0]),
            "tuning": str(plan.split[1]),
            "held_out": str(plan.split[2]),
        },
        "window_count": len(windows),
    }
    chunks = [_canonical_json_line(header)]
    for position, window in enumerate(windows):
        if window.index != position:
            raise ValueError("deterministic publication windows must have contiguous indexes")
        chunks.append(
            _canonical_json_line(
                {
                    "record_type": "window",
                    "position": position,
                    "index": window.index,
                    "start": window.start_time,
                    "end": window.end_time,
                    "reason": window.reason,
                    "query_count": window.query_count,
                    "updates": [
                        {
                            "row": update.row,
                            "col": update.col,
                            "before": update.before,
                            "after": update.after,
                        }
                        for update in window.updates
                    ],
                }
            )
        )
    reconstructed = ReconstructedTrace(
        canonical_jsonl=b"".join(chunks),
        window_count=len(windows),
        warmup_end=warmup_end,
        tuning_end=tuning_end,
        update_events_total=sum(event.kind == EventKind.SET for event in events),
        queries_total=sum(event.kind == EventKind.QUERY for event in events),
        tuning_queries=sum(window.query_count for window in windows[warmup_end:tuning_end]),
        held_out_queries=sum(window.query_count for window in windows[tuning_end:]),
    )
    cache_entry_bytes = len(reconstructed.canonical_jsonl)
    if cache_entry_bytes <= _EXPECTED_TRACE_CACHE_MAX_BYTES:
        while (
            _EXPECTED_TRACE_CACHE
            and _expected_trace_cache_bytes + cache_entry_bytes > _EXPECTED_TRACE_CACHE_MAX_BYTES
        ):
            _evicted_key, evicted = _EXPECTED_TRACE_CACHE.popitem(last=False)
            _expected_trace_cache_bytes -= len(evicted.canonical_jsonl)
        _EXPECTED_TRACE_CACHE[cache_key] = reconstructed
        _expected_trace_cache_bytes += cache_entry_bytes
    return reconstructed


def _validate_trace(
    path: Path,
    *,
    plan: ExperimentPlan,
    plan_sha256: str,
    manifest_sha256: str,
    seed: int,
    workload: str,
    freshness: Fraction,
    ratio: Fraction,
    contract: TraceContract,
) -> TraceEvidence:
    raw = path.read_bytes()
    if not raw or not raw.endswith(b"\n"):
        raise ValueError(f"event-window trace must be nonempty canonical JSONL: {path}")
    try:
        records = [json.loads(line) for line in raw.splitlines()]
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"event-window trace contains invalid JSONL: {path}") from error
    if any(not isinstance(record, dict) for record in records):
        raise ValueError(f"event-window trace records must be objects: {path}")
    if b"".join(_canonical_json_line(record) for record in records) != raw:
        raise ValueError(f"event-window trace is not canonical JSONL: {path}")
    reconstructed = _reconstruct_trace(
        plan=plan,
        plan_sha256=plan_sha256,
        manifest_sha256=manifest_sha256,
        seed=seed,
        workload=workload,
        freshness=freshness,
        ratio=ratio,
        contract=contract,
    )
    if raw != reconstructed.canonical_jsonl:
        raise ValueError(
            f"event-window trace diverges from the deterministic generated stream: {path}"
        )
    return TraceEvidence(
        sha256=hashlib.sha256(raw).hexdigest(),
        initial_state_sha256=contract.initial_state_sha256,
        window_count=reconstructed.window_count,
        warmup_end=reconstructed.warmup_end,
        tuning_end=reconstructed.tuning_end,
        update_events_total=reconstructed.update_events_total,
        queries_total=reconstructed.queries_total,
        tuning_queries=reconstructed.tuning_queries,
        held_out_queries=reconstructed.held_out_queries,
    )


def _validate_metrics(
    path: Path,
    *,
    plan: ExperimentPlan,
    plan_sha256: str,
    manifest_sha256: str,
    seed: int,
    workload: str,
    freshness: Fraction,
    ratio: Fraction,
    trace: TraceEvidence,
) -> None:
    payload = _load_json(path, "cell metrics")
    try:
        validate_causal_payload(
            payload,
            expected_candidate_ids=(candidate.candidate_id for candidate in plan.candidates),
        )
    except (TypeError, ValueError) as error:
        raise ValueError(f"cell metrics causal payload is invalid: {path}: {error}") from error
    records = _list(payload.get("records"), "cell metrics records")
    fixed_records = [
        _mapping(record, "cell metrics record")
        for record in records
        if _mapping(record, "cell metrics record").get("record_kind") == "fixed-candidate"
    ]
    held_out_windows = trace.window_count - trace.tuning_end
    for record in fixed_records:
        for field, expected in (
            ("windows", held_out_windows),
            ("queries", trace.held_out_queries),
        ):
            if _strict_int(record.get(field), f"held-out fixed metrics {field}") != expected:
                raise ValueError(
                    f"held-out fixed metrics {field} does not match reconstructed trace: {path}"
                )
    tuning_aggregates = _list(
        payload.get("tuning_aggregates"),
        "cell metrics tuning_aggregates",
    )
    tuning_windows = trace.tuning_end - trace.warmup_end
    for aggregate in tuning_aggregates:
        tuning_metrics = _mapping(
            _mapping(aggregate, "cell tuning aggregate").get("metrics"),
            "cell tuning aggregate metrics",
        )
        for field, expected in (
            ("windows", tuning_windows),
            ("queries", trace.tuning_queries),
        ):
            if _strict_int(tuning_metrics.get(field), f"tuning metrics {field}") != expected:
                raise ValueError(
                    f"tuning metrics {field} does not match reconstructed trace: {path}"
                )
    metadata = _mapping(payload.get("metadata"), "cell metrics metadata")
    _require_exact_keys(metadata, CELL_METADATA_KEYS, "cell metrics metadata")
    expected_rho_id = rho_path_id(ratio)
    for field, expected in (
        ("workload", workload),
        ("seed", seed + plan.workloads.index(workload) + 1),
        ("suite_seed", seed),
        ("rows", plan.rows),
        ("cols", plan.cols),
        ("initial_nnz_per_row", plan.initial_nnz_per_row),
        ("events_planned", plan.events),
        ("effective_slots", plan.effective_slots),
        ("partition_rows", plan.partition_rows),
        ("layout_measurement_kind", plan.layout_measurement_kind),
        ("freshness_seconds", float(freshness)),
        ("freshness_seconds_fraction", str(freshness)),
        ("queries_per_update_target", float(ratio)),
        ("queries_per_update_fraction", str(ratio)),
        ("rho_id", expected_rho_id),
        (
            "queries_per_update_scheduled",
            trace.queries_total / trace.update_events_total if trace.update_events_total else 0.0,
        ),
        ("update_events_total", trace.update_events_total),
        ("queries_total", trace.queries_total),
        ("held_out_queries", trace.held_out_queries),
        ("windows_total", trace.window_count),
        ("warmup_windows", trace.warmup_end),
        ("tuning_windows", trace.tuning_end - trace.warmup_end),
        ("held_out_windows", trace.window_count - trace.tuning_end),
        ("fixed_candidate_count", len(plan.candidates)),
        ("experiment_plan_sha256", plan_sha256),
        ("manifest_sha256", manifest_sha256),
        ("initial_state_sha256", trace.initial_state_sha256),
        ("event_window_trace_schema", EVENT_WINDOW_TRACE_SCHEMA),
        ("event_window_trace_sha256", trace.sha256),
        ("real_temporal_dataset", False),
        ("state_model", CAUSAL_STATE_MODEL),
        ("measurement_kind", CAUSAL_MEASUREMENT_KIND),
    ):
        try:
            _require_exact_json_value(
                metadata.get(field), expected, f"cell metrics metadata {field}"
            )
        except ValueError as error:
            raise ValueError(f"cell metrics metadata {field} is inconsistent: {path}") from error
    for field in ("gate_eligible", "complete_cost_claim_allowed", "complete_reference_set"):
        _exact_false(metadata.get(field), f"cell metrics metadata {field}")
    span80_by_candidate = _mapping(
        metadata.get("span80_by_candidate"),
        "cell metrics metadata span80_by_candidate",
    )
    expected_candidate_ids = {candidate.candidate_id for candidate in plan.candidates}
    if set(span80_by_candidate) != expected_candidate_ids:
        raise ValueError(f"cell metrics Span80 candidate IDs are inconsistent: {path}")
    for candidate_id, serialized_curve in span80_by_candidate.items():
        curve = _mapping(serialized_curve, f"Span80 curve {candidate_id}")
        if set(curve) != {"1", "2", "4", "8"}:
            raise ValueError(f"cell metrics Span80 curve keys are inconsistent: {path}")
        for interval_count, value in curve.items():
            if type(value) is not float or not math.isfinite(value) or not 0.0 <= value <= 1.0:
                raise ValueError(
                    f"cell metrics Span80[{candidate_id}][{interval_count}] is invalid: {path}"
                )


def _validate_cell(
    shard_dir: Path,
    cell_payload: Mapping[str, object],
    *,
    plan: ExperimentPlan,
    plan_sha256: str,
    manifest_sha256: str,
    seed: int,
    workload: str,
    freshness: Fraction,
    ratio: Fraction,
    trace_contract: TraceContract,
) -> CellEvidence:
    _require_exact_keys(cell_payload, CELL_STATUS_KEYS, "SHARD_STATUS cell")
    rho_id = rho_path_id(ratio)
    expected_relative = (Path(workload) / freshness_path_id(freshness) / rho_id).as_posix()
    if cell_payload.get("relative_path") != expected_relative:
        raise ValueError("cell relative_path does not match its Cartesian identity")
    if cell_payload.get("rho_id") != rho_id or cell_payload.get("rho_fraction") != str(ratio):
        raise ValueError("cell rho identity does not match the experiment plan")
    cell_dir = shard_dir / expected_relative
    if not cell_dir.is_dir():
        raise ValueError(f"cell directory is missing: {cell_dir}")
    expected_names = REQUIRED_CELL_FILES | {"SHA256SUMS"}
    actual_names = {path.name for path in cell_dir.iterdir()}
    if actual_names != expected_names:
        missing_files = sorted(expected_names - actual_names)
        extra_files = sorted(actual_names - expected_names)
        raise ValueError(
            f"cell directory must contain the exact required file set: {cell_dir}; "
            f"missing={missing_files}, extra={extra_files}"
        )
    invalid_file_types = sorted(
        path.name for path in cell_dir.iterdir() if path.is_symlink() or not path.is_file()
    )
    if invalid_file_types:
        raise ValueError(
            f"cell evidence must be regular files without symlinks: {cell_dir}; "
            f"invalid={invalid_file_types}"
        )

    checksums_path = cell_dir / "SHA256SUMS"
    checksums = _parse_checksum_manifest(checksums_path)
    if checksums.keys() != REQUIRED_CELL_FILES:
        missing_checksums = sorted(REQUIRED_CELL_FILES - checksums.keys())
        extra_checksums = sorted(checksums.keys() - REQUIRED_CELL_FILES)
        raise ValueError(
            f"cell must contain the exact required checksum paths: {cell_dir}; "
            f"missing={missing_checksums}, extra={extra_checksums}"
        )
    _validate_checksum_targets(cell_dir, checksums)
    if cell_payload.get("cell_checksums_sha256") != _sha256(checksums_path):
        raise ValueError(f"cell_checksums_sha256 is inconsistent: {cell_dir}")

    trace = _validate_trace(
        cell_dir / "event-window-trace.jsonl",
        plan=plan,
        plan_sha256=plan_sha256,
        manifest_sha256=manifest_sha256,
        seed=seed,
        workload=workload,
        freshness=freshness,
        ratio=ratio,
        contract=trace_contract,
    )
    if cell_payload.get("event_window_trace_sha256") != trace.sha256:
        raise ValueError(f"event_window_trace_sha256 is inconsistent: {cell_dir}")
    _validate_metrics(
        cell_dir / "metrics.json",
        plan=plan,
        plan_sha256=plan_sha256,
        manifest_sha256=manifest_sha256,
        seed=seed,
        workload=workload,
        freshness=freshness,
        ratio=ratio,
        trace=trace,
    )
    return CellEvidence(
        source=cell_dir,
        cell_id=expected_relative,
        trace_sha256=trace.sha256,
        initial_state_sha256=trace.initial_state_sha256,
    )


def _validate_shard(
    shard_dir: Path,
    *,
    plan: ExperimentPlan,
    plan_sha256: str,
    manifest_sha256: str,
    seed: int,
    expected_preflight: Mapping[str, object],
    trace_contract: TraceContract,
) -> ShardEvidence:
    status = _load_json(shard_dir / "SHARD_STATUS.json", "SHARD_STATUS")
    _require_exact_keys(status, SHARD_STATUS_KEYS, "SHARD_STATUS")
    for field, expected in (
        ("schema", CAUSAL_SCHEMA),
        ("state_model", CAUSAL_STATE_MODEL),
        ("measurement_kind", CAUSAL_MEASUREMENT_KIND),
        ("seed", seed),
        ("experiment_plan_sha256", plan_sha256),
        ("manifest_sha256", manifest_sha256),
        ("experiment_plan_version", plan.plan_version),
    ):
        try:
            _require_exact_json_value(status.get(field), expected, f"SHARD_STATUS {field}")
        except ValueError as error:
            raise ValueError(f"SHARD_STATUS {field} is inconsistent in {shard_dir}") from error
    for field in (
        "gate_eligible",
        "complete_cost_claim_allowed",
        "complete_reference_set",
        "suite_complete",
    ):
        _exact_false(status.get(field), f"SHARD_STATUS {field}")
    try:
        _require_exact_json_value(
            status.get("deferred_reference_baselines"),
            list(DEFERRED_REFERENCE_BASELINES),
            "SHARD_STATUS deferred_reference_baselines",
        )
    except ValueError as error:
        raise ValueError(
            f"SHARD_STATUS deferred reference baseline is inconsistent: {shard_dir}"
        ) from error
    for field, expected in (
        ("effective_slots", plan.effective_slots),
        ("partition_rows", plan.partition_rows),
        ("layout_measurement_kind", plan.layout_measurement_kind),
        (
            "planned_bandwidth_profiles_mbps",
            [float(value) for value in plan.bandwidth_profiles_mbps],
        ),
        ("deferred_unpriced_plan_dimensions", ["bandwidth_profiles_mbps"]),
        ("preflight", dict(expected_preflight)),
    ):
        _require_exact_json_value(status.get(field), expected, f"SHARD_STATUS {field}")

    workload = status.get("workload")
    if not isinstance(workload, str) or workload not in plan.workloads:
        raise ValueError(f"SHARD_STATUS workload is not in the experiment plan: {shard_dir}")
    freshness = _exact_fraction(
        status.get("freshness_seconds_fraction"),
        "SHARD_STATUS freshness_seconds_fraction",
    )
    if type(status.get("freshness_seconds_fraction")) is not str:
        raise ValueError(
            f"SHARD_STATUS freshness_seconds_fraction must be an exact string: {shard_dir}"
        )
    if freshness not in plan.freshness_seconds:
        raise ValueError(f"SHARD_STATUS freshness is not in the experiment plan: {shard_dir}")
    numeric_freshness = _exact_fraction(
        status.get("freshness_seconds"),
        "SHARD_STATUS freshness_seconds",
    )
    if numeric_freshness != freshness:
        raise ValueError(f"SHARD_STATUS freshness fields disagree: {shard_dir}")
    _require_exact_json_value(
        status.get("freshness_seconds"),
        float(freshness),
        "SHARD_STATUS freshness_seconds",
    )

    expected_rho_ids = [rho_path_id(ratio) for ratio in plan.ratio_grid]
    try:
        _require_exact_json_value(status.get("rho_ids"), expected_rho_ids, "SHARD_STATUS rho_ids")
    except ValueError as error:
        raise ValueError(
            f"SHARD_STATUS rho_ids must be the exact nine planned IDs: {shard_dir}"
        ) from error
    if (
        status.get("cells_expected") != R2_RHO_COUNT
        or status.get("cells_completed") != R2_RHO_COUNT
    ):
        raise ValueError(f"SHARD_STATUS must report 9/9 cells: {shard_dir}")
    candidate_ids = sorted(candidate.candidate_id for candidate in plan.candidates)
    try:
        _require_exact_json_value(
            status.get("candidate_ids"), candidate_ids, "SHARD_STATUS candidate_ids"
        )
    except ValueError as error:
        raise ValueError(
            f"SHARD_STATUS candidate_ids contradict the plan interface: {shard_dir}"
        ) from error
    cell_payloads = _list(status.get("cells"), "SHARD_STATUS cells")
    if len(cell_payloads) != R2_RHO_COUNT:
        raise ValueError(f"SHARD_STATUS must contain exactly nine cell entries: {shard_dir}")
    cells = tuple(
        _validate_cell(
            shard_dir,
            _mapping(cell_payload, "SHARD_STATUS cell"),
            plan=plan,
            plan_sha256=plan_sha256,
            manifest_sha256=manifest_sha256,
            seed=seed,
            workload=workload,
            freshness=freshness,
            ratio=ratio,
            trace_contract=trace_contract,
        )
        for cell_payload, ratio in zip(cell_payloads, plan.ratio_grid, strict=True)
    )
    if len({cell.cell_id for cell in cells}) != R2_RHO_COUNT:
        raise ValueError(f"duplicate cell identity inside shard: {shard_dir}")

    expected_root_checksum_paths = _validate_exact_shard_tree(shard_dir, cells)
    root_checksums = _parse_checksum_manifest(shard_dir / "SHA256SUMS")
    if root_checksums.keys() != expected_root_checksum_paths:
        raise ValueError(
            f"shard must contain the exact root checksum paths: {shard_dir}; "
            f"missing={sorted(expected_root_checksum_paths - root_checksums.keys())}, "
            f"extra={sorted(root_checksums.keys() - expected_root_checksum_paths)}"
        )
    _validate_checksum_targets(shard_dir, root_checksums)
    return ShardEvidence(shard_dir.name, workload, freshness, cells)


def _write_root_checksums(output_dir: Path) -> None:
    checksum_path = output_dir / "SHA256SUMS"
    lines = []
    for path in sorted(output_dir.rglob("*")):
        if not path.is_file() or path == checksum_path:
            continue
        lines.append(f"{_sha256(path)}  {path.relative_to(output_dir).as_posix()}")
    checksum_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def aggregate_shards(
    *,
    shards_dir: Path,
    output_dir: Path,
    experiment_plan: Path,
    manifest: Path,
    seed: int,
) -> dict[str, object]:
    """Validate all downloaded shard artifacts before materializing a complete suite."""

    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be a strict integer")
    plan = load_experiment_plan(experiment_plan)
    _validate_plan_shape(plan)
    manifest_payload = load_manifest(manifest)
    expected_preflight = asdict(run_day1_preflight(manifest_payload))
    freshness_contract = _mapping(manifest_payload.get("freshness"), "manifest.freshness")
    microbatch_max_updates = _strict_int(
        freshness_contract.get("microbatch_max_updates"),
        "manifest.freshness.microbatch_max_updates",
        minimum=1,
    )
    query_requires_latest = freshness_contract.get("query_requires_latest")
    if type(query_requires_latest) is not bool:
        raise ValueError("manifest.freshness.query_requires_latest must be an exact bool")
    integer_correctness = _mapping(
        manifest_payload.get("integer_correctness"),
        "manifest.integer_correctness",
    )
    matrix_entry_abs_bound = _strict_int(
        integer_correctness.get("matrix_entry_abs_bound"),
        "manifest.integer_correctness.matrix_entry_abs_bound",
        minimum=1,
    )
    initial_state = generate_initial_matrix(
        plan.rows,
        plan.cols,
        plan.initial_nnz_per_row,
        seed=seed,
        matrix_entry_abs_bound=matrix_entry_abs_bound,
    )
    trace_contract = TraceContract(
        initial_state=initial_state,
        initial_state_sha256=_initial_state_sha256(initial_state),
        microbatch_max_updates=microbatch_max_updates,
        query_requires_latest=query_requires_latest,
        matrix_entry_abs_bound=matrix_entry_abs_bound,
    )
    plan_sha256 = _sha256(experiment_plan)
    manifest_sha256 = _sha256(manifest)
    if not shards_dir.is_dir():
        raise ValueError(f"shards directory does not exist: {shards_dir}")
    shard_dirs = sorted(shards_dir.iterdir())
    if len(shard_dirs) != R2_SHARD_COUNT or any(
        path.is_symlink() or not path.is_dir() for path in shard_dirs
    ):
        raise ValueError(
            "expected exactly 21 shard artifacts as regular directories in downloaded layout, "
            f"found entries={[path.name for path in shard_dirs]}"
        )

    shards: list[ShardEvidence] = []
    shard_keys: set[tuple[str, Fraction]] = set()
    for shard_dir in shard_dirs:
        shard = _validate_shard(
            shard_dir,
            plan=plan,
            plan_sha256=plan_sha256,
            manifest_sha256=manifest_sha256,
            seed=seed,
            expected_preflight=expected_preflight,
            trace_contract=trace_contract,
        )
        key = (shard.workload, shard.freshness)
        if key in shard_keys:
            raise ValueError(f"duplicate shard identity: {key}")
        shard_keys.add(key)
        shards.append(shard)

    expected_shard_keys = {
        (workload, freshness) for workload in plan.workloads for freshness in plan.freshness_seconds
    }
    if shard_keys != expected_shard_keys:
        missing = sorted(expected_shard_keys - shard_keys)
        extra = sorted(shard_keys - expected_shard_keys)
        raise ValueError(f"shard Cartesian product is incomplete; missing={missing}, extra={extra}")
    cells = [cell for shard in shards for cell in shard.cells]
    cell_ids = [cell.cell_id for cell in cells]
    if len(cells) != R2_CELL_COUNT or len(set(cell_ids)) != R2_CELL_COUNT:
        raise ValueError("expected exactly 189 unique cells with no missing or duplicate cell")
    initial_state_digests = {cell.initial_state_sha256 for cell in cells}
    if len(initial_state_digests) != 1:
        raise ValueError("initial-state digest must be consistent across all 189 cells")
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError(f"output directory must be absent or empty: {output_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)
    for cell in cells:
        destination = output_dir / cell.cell_id
        destination.mkdir(parents=True, exist_ok=False)
        for filename in sorted(REQUIRED_CELL_FILES | {"SHA256SUMS"}):
            shutil.copy2(cell.source / filename, destination / filename)
    sorted_cell_ids = sorted(cell_ids)
    status: dict[str, object] = {
        "schema": CAUSAL_SCHEMA,
        "state_model": CAUSAL_STATE_MODEL,
        "measurement_kind": CAUSAL_MEASUREMENT_KIND,
        "gate_eligible": False,
        "complete_cost_claim_allowed": False,
        "complete_reference_set": False,
        "suite_complete": True,
        "deferred_reference_baselines": list(DEFERRED_REFERENCE_BASELINES),
        "seed": seed,
        "experiment_plan_sha256": plan_sha256,
        "manifest_sha256": manifest_sha256,
        "experiment_plan_version": plan.plan_version,
        "event_window_trace_schema": EVENT_WINDOW_TRACE_SCHEMA,
        "initial_state_sha256": next(iter(initial_state_digests)),
        "candidate_ids": sorted(candidate.candidate_id for candidate in plan.candidates),
        "effective_slots": plan.effective_slots,
        "partition_rows": plan.partition_rows,
        "layout_measurement_kind": plan.layout_measurement_kind,
        "planned_bandwidth_profiles_mbps": [float(value) for value in plan.bandwidth_profiles_mbps],
        "deferred_unpriced_plan_dimensions": ["bandwidth_profiles_mbps"],
        "preflight": expected_preflight,
        "workloads": list(plan.workloads),
        "freshness_seconds_fractions": [str(value) for value in plan.freshness_seconds],
        "rho_ids": [rho_path_id(value) for value in plan.ratio_grid],
        "shards_expected": R2_SHARD_COUNT,
        "shards_completed": len(shards),
        "cells_expected": R2_CELL_COUNT,
        "cells_completed": len(cells),
        "shard_artifacts": [shard.artifact_name for shard in shards],
        "cell_ids": sorted_cell_ids,
    }
    (output_dir / "SUITE_STATUS.json").write_text(
        json.dumps(status, indent=2, sort_keys=True, allow_nan=False),
        encoding="utf-8",
    )
    _write_root_checksums(output_dir)
    return status


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Fail-closed aggregation of downloaded-shards/<artifact-name>/SHARD_STATUS.json"
        )
    )
    parser.add_argument("--shards-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--experiment-plan", default=Path("config/experiment_plan.json"), type=Path)
    parser.add_argument("--manifest", default=Path("config/params_manifest.json"), type=Path)
    parser.add_argument("--seed", required=True, type=int)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    aggregate_shards(
        shards_dir=args.shards_dir,
        output_dir=args.output_dir,
        experiment_plan=args.experiment_plan,
        manifest=args.manifest,
        seed=args.seed,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
