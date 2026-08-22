#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass, replace
from fractions import Fraction
from math import isfinite
from pathlib import Path

from dynamic_cssc.events import Event, EventKind, PublicationWindow, publication_windows
from dynamic_cssc.manifest import load_manifest
from dynamic_cssc.metrics import StrategyMetrics, UnitCosts
from dynamic_cssc.preflight import run_day1_preflight
from dynamic_cssc.report import (
    CAUSAL_MEASUREMENT_KIND,
    CAUSAL_SCHEMA,
    CAUSAL_STATE_MODEL,
    CausalMetricRecord,
    write_causal_plots,
    write_causal_records,
    write_causal_summary,
    write_checksums,
)
from dynamic_cssc.selection import (
    ExperimentSplit,
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
    simulate_targets,
)
from dynamic_cssc.span80 import span80_curve
from dynamic_cssc.workloads import (
    SYNTHETIC_WORKLOADS,
    generate_event_stream,
    generate_initial_matrix,
)

WORKLOADS = SYNTHETIC_WORKLOADS
EVENT_WINDOW_TRACE_SCHEMA = "day1-event-window-trace-v2"
LAYOUT_MEASUREMENT_KIND = "synthetic-proxy"
DEFERRED_REFERENCE_BASELINES = ("strong-packed-coo",)
_CANONICAL_SEED = re.compile(r"(?:0|[1-9][0-9]*)")
_MAX_SUITE_SEED = (1 << 63) - 1 - len(WORKLOADS)

PLAN_KEYS = frozenset(
    {
        "plan_version",
        "split",
        "synthetic",
        "reserved_slack_betas",
        "periodic_repack_windows",
        "freshness_seconds",
        "bandwidth_profiles_mbps",
    }
)
SPLIT_KEYS = frozenset({"warmup", "tuning", "held_out"})
SYNTHETIC_KEYS = frozenset(
    {
        "rows",
        "cols",
        "initial_nnz_per_row",
        "events",
        "effective_slots",
        "partition_rows",
        "layout_measurement_kind",
        "queries_per_update_grid",
        "workloads",
    }
)


@dataclass(frozen=True, slots=True)
class CausalCellResult:
    warmup_end: int
    tuning_end: int
    tuning_results: dict[str, SimulationResult]
    fixed_results: dict[str, SimulationResult]
    selected_candidate_id: str
    tuned_policy: StrategyMetrics
    oracle_candidate_id: str
    offline_oracle: StrategyMetrics


@dataclass(frozen=True, slots=True)
class ExperimentPlan:
    plan_version: str
    split: ExperimentSplit
    rows: int
    cols: int
    initial_nnz_per_row: int
    events: int
    effective_slots: int
    partition_rows: int
    layout_measurement_kind: str
    ratio_grid: tuple[Fraction, ...]
    workloads: tuple[str, ...]
    candidates: tuple[FixedCandidate, ...]
    freshness_seconds: tuple[Fraction, ...]
    bandwidth_profiles_mbps: tuple[Fraction, ...]


def _candidate_config(base_config: SimulationConfig, candidate: FixedCandidate) -> SimulationConfig:
    changes: dict[str, object] = {}
    if candidate.reserved_slack_beta is not None:
        changes["reserved_slack_beta"] = float(candidate.reserved_slack_beta)
    if candidate.periodic_repack_windows is not None:
        changes["periodic_repack_windows"] = candidate.periodic_repack_windows
    if candidate.packed_coo_segment_capacity is not None:
        changes["packed_coo_segment_capacity"] = candidate.packed_coo_segment_capacity
    return replace(base_config, **changes)


def _candidate_targets(
    base_config: SimulationConfig, candidates: tuple[FixedCandidate, ...]
) -> list[SimulationTarget]:
    return [
        SimulationTarget(
            run_id=candidate.candidate_id,
            strategy=candidate.strategy,
            config=_candidate_config(base_config, candidate),
        )
        for candidate in candidates
    ]


def _validate_candidate_results(
    candidates: tuple[FixedCandidate, ...],
    results: dict[str, SimulationResult],
) -> None:
    expected_ids = {candidate.candidate_id for candidate in candidates}
    actual_ids = set(results)
    if actual_ids != expected_ids:
        raise ValueError(
            "simulation result IDs must exactly match fixed candidate IDs; "
            f"missing={sorted(expected_ids - actual_ids)}, "
            f"extra={sorted(actual_ids - expected_ids)}"
        )
    for candidate in candidates:
        result = results[candidate.candidate_id]
        if not isinstance(result, SimulationResult):
            raise TypeError("simulation results must be SimulationResult values")
        if result.metrics.strategy != candidate.strategy:
            raise ValueError(f"simulation result strategy contradicts {candidate.candidate_id}")


def evaluate_causal_cell(
    *,
    windows: list[PublicationWindow],
    initial_state: dict[tuple[int, int], int],
    base_config: SimulationConfig,
    split: ExperimentSplit,
    candidates: tuple[FixedCandidate, ...],
    costs: UnitCosts,
    simulate_targets_fn: Callable[..., dict[str, SimulationResult]] | None = None,
) -> CausalCellResult:
    """Tune fixed candidates on a prefix, freeze one, then replay held-out causally."""

    run_simulation = simulate_targets if simulate_targets_fn is None else simulate_targets_fn
    warmup_end, tuning_end = split_boundaries(len(windows), split)
    targets = _candidate_targets(base_config, candidates)
    tuning_replay = windows[:tuning_end]
    tuning_results = run_simulation(
        tuning_replay,
        initial_state,
        targets,
        measure_from=warmup_end,
    )
    _validate_candidate_results(candidates, tuning_results)
    tuning_metrics = {
        candidate_id: result.metrics for candidate_id, result in tuning_results.items()
    }

    selected = select_tuned_fixed_candidate(candidates, tuning_metrics, costs)

    fixed_results = run_simulation(
        windows,
        initial_state,
        targets,
        measure_from=tuning_end,
    )
    _validate_candidate_results(candidates, fixed_results)
    fixed_metrics = {candidate_id: result.metrics for candidate_id, result in fixed_results.items()}

    selected_metric = fixed_metrics[selected.candidate_id]
    tuned_policy = replace(
        selected_metric,
        strategy="TunedFixedPolicy",
        category="tuned-fixed-policy",
        source="tuning-prefix-frozen",
    )
    ranked_oracle = [
        (metric.predicted_time(costs), candidate_id)
        for candidate_id, metric in fixed_metrics.items()
        if isfinite(metric.predicted_time(costs))
    ]
    if not ranked_oracle:
        raise ValueError("no fixed candidate has a finite held-out predicted_time")
    _, oracle_candidate_id = min(ranked_oracle)
    offline_oracle = replace(
        fixed_metrics[oracle_candidate_id],
        strategy="BestFixed-Offline-Oracle",
        category="diagnostic-oracle",
        source="held-out-hindsight-diagnostic",
    )
    return CausalCellResult(
        warmup_end=warmup_end,
        tuning_end=tuning_end,
        tuning_results=tuning_results,
        fixed_results=fixed_results,
        selected_candidate_id=selected.candidate_id,
        tuned_policy=tuned_policy,
        oracle_candidate_id=oracle_candidate_id,
        offline_oracle=offline_oracle,
    )


def insert_queries_by_ratio(
    events: Iterable[Event], queries_per_update: Fraction | int | float | str
) -> list[Event]:
    """Insert a deterministic query schedule using exact rational arithmetic."""

    ratio = (
        queries_per_update
        if isinstance(queries_per_update, Fraction)
        else Fraction(str(queries_per_update))
    )
    if ratio < 0:
        raise ValueError("queries_per_update must be nonnegative")

    scheduled: list[Event] = []
    remainder = 0
    for event in events:
        if event.kind == EventKind.QUERY:
            raise ValueError("base events must not contain queries")
        scheduled.append(event)
        if event.kind != EventKind.SET:
            continue
        remainder += ratio.numerator
        query_count, remainder = divmod(remainder, ratio.denominator)
        scheduled.extend(Event.query(event.timestamp) for _ in range(query_count))
    return scheduled


def parse_canonical_seed(raw_seed: object) -> int:
    """Parse one canonical nonnegative decimal integer without normalization ambiguity."""

    if type(raw_seed) is int:
        if 0 <= raw_seed <= _MAX_SUITE_SEED:
            return raw_seed
    elif (
        type(raw_seed) is str
        and len(raw_seed) <= len(str(_MAX_SUITE_SEED))
        and _CANONICAL_SEED.fullmatch(raw_seed) is not None
    ):
        seed = int(raw_seed)
        if seed <= _MAX_SUITE_SEED:
            return seed
    raise ValueError("seed must be a canonical nonnegative integer")


def _path_fraction(value: Fraction | int | float | str, field: str) -> Fraction:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an exact nonnegative fraction")
    try:
        fraction = value if isinstance(value, Fraction) else Fraction(str(value))
    except (ValueError, ZeroDivisionError) as error:
        raise ValueError(f"{field} must be an exact nonnegative fraction") from error
    if fraction < 0:
        raise ValueError(f"{field} must be an exact nonnegative fraction")
    return fraction


def fraction_path_token(value: Fraction | int | float | str) -> str:
    """Encode one exact nonnegative fraction as an injective path-safe token."""

    fraction = _path_fraction(value, "path fraction")
    return f"n{fraction.numerator}d{fraction.denominator}"


def rho_path_id(value: Fraction | int | float | str) -> str:
    return f"rho-{fraction_path_token(value)}"


def freshness_path_id(value: Fraction | int | float | str) -> str:
    fraction = _path_fraction(value, "freshness")
    if fraction == 0:
        raise ValueError("freshness must be positive")
    return f"freshness-{fraction_path_token(fraction)}s"


def _sha256_file(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _canonical_json_line(payload: Mapping[str, object]) -> bytes:
    return (
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
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


def write_event_window_trace(
    path: Path,
    *,
    windows: list[PublicationWindow],
    workload: str,
    freshness_seconds: Fraction,
    ratio: Fraction,
    experiment_plan_sha256: str,
    manifest_sha256: str,
    seed: int,
    workload_seed: int,
    rows: int,
    cols: int,
    initial_nnz_per_row: int,
    effective_slots: int,
    partition_rows: int,
    layout_measurement_kind: str,
    initial_state_sha256: str,
    microbatch_max_updates: int,
    query_requires_latest: bool,
    split: ExperimentSplit,
) -> str:
    """Write one canonical, candidate-independent publication-window trace."""

    header: dict[str, object] = {
        "record_type": "header",
        "schema": EVENT_WINDOW_TRACE_SCHEMA,
        "cell": {
            "workload": workload,
            "freshness_seconds_fraction": str(freshness_seconds),
            "rho_fraction": str(ratio),
            "rho_id": rho_path_id(ratio),
        },
        "experiment_plan_sha256": experiment_plan_sha256,
        "manifest_sha256": manifest_sha256,
        "seed": seed,
        "workload_seed": workload_seed,
        "matrix": {
            "rows": rows,
            "cols": cols,
            "initial_nnz_per_row": initial_nnz_per_row,
        },
        "effective_slots": effective_slots,
        "partition_rows": partition_rows,
        "layout_measurement_kind": layout_measurement_kind,
        "initial_state_sha256": initial_state_sha256,
        "initial_state_digest_algorithm": "sha256-canonical-json-v1",
        "microbatch_max_updates": microbatch_max_updates,
        "query_requires_latest": query_requires_latest,
        "split": {
            "warmup": str(split[0]),
            "tuning": str(split[1]),
            "held_out": str(split[2]),
        },
        "window_count": len(windows),
    }
    chunks = [_canonical_json_line(header)]
    for position, window in enumerate(windows):
        if window.index != position:
            raise ValueError(
                "publication window indexes must be contiguous and match trace positions"
            )
        record: dict[str, object] = {
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
        chunks.append(_canonical_json_line(record))
    canonical = b"".join(chunks)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical)
    return hashlib.sha256(canonical).hexdigest()


def load_experiment_plan(path: str | Path) -> ExperimentPlan:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("experiment plan must be a JSON object")
    return parse_experiment_plan(payload)


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    return value


def _require_exact_keys(values: Mapping[str, object], expected: frozenset[str], field: str) -> None:
    actual = set(values)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        raise ValueError(
            f"{field} keys must exactly match the frozen plan schema; "
            f"missing={missing}, extra={extra}"
        )


def _strict_int(value: object, field: str, *, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        qualifier = "positive" if minimum == 1 else "nonnegative"
        raise ValueError(f"{field} must be a {qualifier} strict integer")
    return value


def _positive_fraction_grid(value: object, field: str) -> tuple[Fraction, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{field} must be a nonempty list")
    parsed: list[Fraction] = []
    for item in value:
        if isinstance(item, bool):
            raise ValueError(f"{field} values must be positive finite numbers")
        try:
            number = Fraction(str(item))
        except (ValueError, ZeroDivisionError) as error:
            raise ValueError(f"{field} values must be positive finite numbers") from error
        if number <= 0:
            raise ValueError(f"{field} values must be positive finite numbers")
        parsed.append(number)
    if len(parsed) != len(set(parsed)):
        raise ValueError(f"{field} must not contain duplicates")
    return tuple(parsed)


def _ratio_grid(synthetic: Mapping[str, object]) -> tuple[Fraction, ...]:
    raw_grid = synthetic.get("queries_per_update_grid")
    if not isinstance(raw_grid, list) or not raw_grid:
        raise ValueError("queries_per_update_grid must be a nonempty list")
    ratios = []
    for value in raw_grid:
        if isinstance(value, bool):
            raise ValueError("queries_per_update_grid values must be nonnegative fractions")
        try:
            ratio = Fraction(str(value))
        except (ValueError, ZeroDivisionError) as error:
            raise ValueError(
                "queries_per_update_grid values must be nonnegative fractions"
            ) from error
        if ratio < 0:
            raise ValueError("queries_per_update_grid values must be nonnegative fractions")
        ratios.append(ratio)
    if len(ratios) != len(set(ratios)):
        raise ValueError("queries_per_update_grid must not contain duplicates")
    return tuple(ratios)


def _workloads(synthetic: Mapping[str, object]) -> tuple[str, ...]:
    raw_workloads = synthetic.get("workloads")
    if not isinstance(raw_workloads, list) or not raw_workloads:
        raise ValueError("synthetic.workloads must be a nonempty list")
    if any(not isinstance(workload, str) for workload in raw_workloads):
        raise ValueError("synthetic.workloads must contain strings")
    workloads = tuple(raw_workloads)
    unknown = sorted(set(workloads) - set(WORKLOADS))
    if unknown:
        raise ValueError(f"unknown workload(s): {', '.join(unknown)}")
    if len(workloads) != len(set(workloads)):
        raise ValueError("synthetic.workloads must not contain duplicates")
    return workloads


def parse_experiment_plan(payload: Mapping[str, object]) -> ExperimentPlan:
    """Validate the complete frozen Day-1 plan at its JSON trust boundary."""

    _require_exact_keys(payload, PLAN_KEYS, "experiment plan")
    plan_version = payload["plan_version"]
    if plan_version != "0.2.0":
        raise ValueError("plan_version must equal the frozen value 0.2.0")

    split_payload = _mapping(payload["split"], "split")
    _require_exact_keys(split_payload, SPLIT_KEYS, "split")
    split = parse_experiment_split(split_payload)

    synthetic = _mapping(payload["synthetic"], "synthetic")
    _require_exact_keys(synthetic, SYNTHETIC_KEYS, "synthetic")
    rows = _strict_int(synthetic["rows"], "synthetic.rows", minimum=1)
    cols = _strict_int(synthetic["cols"], "synthetic.cols", minimum=1)
    initial_nnz_per_row = _strict_int(
        synthetic["initial_nnz_per_row"],
        "synthetic.initial_nnz_per_row",
        minimum=0,
    )
    if initial_nnz_per_row > cols:
        raise ValueError("synthetic.initial_nnz_per_row must not exceed synthetic.cols")
    events = _strict_int(synthetic["events"], "synthetic.events", minimum=1)
    effective_slots = _strict_int(
        synthetic["effective_slots"], "synthetic.effective_slots", minimum=1
    )
    if effective_slots != 2048:
        raise ValueError("synthetic.effective_slots must equal the frozen value 2048")
    partition_rows = _strict_int(synthetic["partition_rows"], "synthetic.partition_rows", minimum=1)
    if partition_rows != 128:
        raise ValueError("synthetic.partition_rows must equal the frozen value 128")
    layout_measurement_kind = synthetic["layout_measurement_kind"]
    if layout_measurement_kind != LAYOUT_MEASUREMENT_KIND:
        raise ValueError(
            "synthetic.layout_measurement_kind must equal the frozen value "
            f"{LAYOUT_MEASUREMENT_KIND}"
        )
    ratio_grid = _ratio_grid(synthetic)
    workloads = _workloads(synthetic)

    raw_betas = payload["reserved_slack_betas"]
    raw_periods = payload["periodic_repack_windows"]
    if not isinstance(raw_betas, list):
        raise ValueError("reserved_slack_betas must be a list")
    if not isinstance(raw_periods, list):
        raise ValueError("periodic_repack_windows must be a list")
    candidates = build_fixed_candidates(
        reserved_slack_betas=raw_betas,
        periodic_repack_windows=raw_periods,
    )
    freshness_seconds = _positive_fraction_grid(payload["freshness_seconds"], "freshness_seconds")
    bandwidth_profiles_mbps = _positive_fraction_grid(
        payload["bandwidth_profiles_mbps"], "bandwidth_profiles_mbps"
    )
    return ExperimentPlan(
        plan_version=plan_version,
        split=split,
        rows=rows,
        cols=cols,
        initial_nnz_per_row=initial_nnz_per_row,
        events=events,
        effective_slots=effective_slots,
        partition_rows=partition_rows,
        layout_measurement_kind=layout_measurement_kind,
        ratio_grid=ratio_grid,
        workloads=workloads,
        candidates=candidates,
        freshness_seconds=freshness_seconds,
        bandwidth_profiles_mbps=bandwidth_profiles_mbps,
    )


def _candidate_records(
    candidates: tuple[FixedCandidate, ...], result: CausalCellResult
) -> list[CausalMetricRecord]:
    candidate_by_id = {candidate.candidate_id: candidate for candidate in candidates}
    records = [
        CausalMetricRecord(
            "fixed-candidate",
            candidate.candidate_id,
            candidate.candidate_id,
            candidate.strategy,
            "fixed-candidate",
            result.fixed_results[candidate.candidate_id].metrics,
        )
        for candidate in candidates
    ]
    records.extend(
        [
            CausalMetricRecord(
                "tuned-fixed-policy",
                result.selected_candidate_id,
                "TunedFixedPolicy",
                candidate_by_id[result.selected_candidate_id].strategy,
                "tuning-prefix-only",
                result.tuned_policy,
            ),
            CausalMetricRecord(
                "diagnostic-oracle",
                result.oracle_candidate_id,
                "BestFixed-Offline-Oracle",
                candidate_by_id[result.oracle_candidate_id].strategy,
                "held-out-hindsight-diagnostic-only",
                result.offline_oracle,
            ),
        ]
    )
    return records


def _candidate_span80(
    rows: int,
    candidates: tuple[FixedCandidate, ...],
    result: CausalCellResult,
) -> dict[str, dict[int, float]]:
    curves: dict[str, dict[int, float]] = {}
    for candidate in candidates:
        overflow_by_row = result.fixed_results[candidate.candidate_id].overflow_by_row
        for row, count in overflow_by_row.items():
            if (
                isinstance(row, bool)
                or not isinstance(row, int)
                or not 0 <= row < rows
                or isinstance(count, bool)
                or not isinstance(count, int)
                or count < 0
            ):
                raise ValueError(f"invalid measured overflow_by_row for {candidate.candidate_id}")
        curves[candidate.candidate_id] = span80_curve(
            [overflow_by_row.get(row, 0) for row in range(rows)]
        )
    return curves


def _plan_dimension(
    args: argparse.Namespace,
    argument_name: str,
    planned_value: int,
    plan_field: str,
) -> int:
    override = getattr(args, argument_name, None)
    if override is not None and (type(override) is not int or override != planned_value):
        raise ValueError(
            f"--{argument_name.replace('_', '-')}={override} must equal "
            f"{plan_field}={planned_value}"
        )
    return planned_value


def _selected_shard(
    args: argparse.Namespace,
    experiment_plan: ExperimentPlan,
) -> tuple[str, Fraction]:
    workload = getattr(args, "workload", None)
    if not isinstance(workload, str) or not workload:
        raise ValueError("--workload is required for one Day-1 shard")
    if workload not in experiment_plan.workloads:
        raise ValueError(
            f"--workload={workload} must belong to synthetic.workloads in the experiment plan"
        )

    raw_freshness = getattr(args, "freshness_seconds", None)
    if raw_freshness is None or isinstance(raw_freshness, bool):
        raise ValueError("--freshness-seconds is required for one Day-1 shard")
    try:
        freshness_seconds = (
            raw_freshness if isinstance(raw_freshness, Fraction) else Fraction(str(raw_freshness))
        )
    except (ValueError, ZeroDivisionError) as error:
        raise ValueError("--freshness-seconds must be an exact positive fraction") from error
    if freshness_seconds not in experiment_plan.freshness_seconds:
        raise ValueError(
            f"--freshness-seconds={raw_freshness} must belong to freshness_seconds "
            "in the experiment plan"
        )
    return workload, freshness_seconds


def run_suite(args: argparse.Namespace) -> int:
    # This is intentionally the only suite-level preflight call, and nothing from the
    # experiment plan or workload pipeline is touched until it succeeds.
    seed = parse_canonical_seed(args.seed)
    manifest = load_manifest(args.manifest)
    preflight_report = run_day1_preflight(manifest)

    experiment_plan = load_experiment_plan(args.experiment_plan)
    workload, selected_freshness_seconds = _selected_shard(args, experiment_plan)
    rows = _plan_dimension(args, "rows", experiment_plan.rows, "synthetic.rows")
    cols = _plan_dimension(args, "cols", experiment_plan.cols, "synthetic.cols")
    nnz_per_row = _plan_dimension(
        args,
        "nnz_per_row",
        experiment_plan.initial_nnz_per_row,
        "synthetic.initial_nnz_per_row",
    )
    updates = _plan_dimension(args, "updates", experiment_plan.events, "synthetic.events")
    effective_slots = _plan_dimension(
        args,
        "effective_slots",
        experiment_plan.effective_slots,
        "synthetic.effective_slots",
    )
    partition_rows = _plan_dimension(
        args,
        "partition_rows",
        experiment_plan.partition_rows,
        "synthetic.partition_rows",
    )
    experiment_plan_sha256 = _sha256_file(args.experiment_plan)
    manifest_sha256 = _sha256_file(args.manifest)
    split = experiment_plan.split
    ratio_grid = experiment_plan.ratio_grid
    candidates = experiment_plan.candidates

    integer_correctness = _mapping(
        manifest.get("integer_correctness"), "manifest.integer_correctness"
    )
    matrix_entry_abs_bound = int(integer_correctness["matrix_entry_abs_bound"])
    initial = generate_initial_matrix(
        rows,
        cols,
        nnz_per_row,
        seed=seed,
        matrix_entry_abs_bound=matrix_entry_abs_bound,
    )
    initial_state_sha256 = _initial_state_sha256(initial)
    freshness = _mapping(manifest.get("freshness"), "manifest.freshness")
    query_requires_latest = freshness.get("query_requires_latest")
    if type(query_requires_latest) is not bool:
        raise ValueError("manifest.freshness.query_requires_latest must be an exact bool")
    matrix = manifest.get("matrix", {})
    if not isinstance(matrix, dict):
        raise ValueError("manifest.matrix must be an object")
    max_row_nnz = int(matrix.get("max_nnz_per_row", cols))
    base_config = SimulationConfig(
        rows=rows,
        cols=cols,
        effective_slots=effective_slots,
        partition_rows=partition_rows,
        matrix_value_bound=matrix_entry_abs_bound,
        max_row_nnz=max_row_nnz,
        reserved_slack_beta=0.1,
        periodic_repack_windows=4,
        packed_coo_segment_capacity=128,
    )
    costs = UnitCosts()
    cells: list[dict[str, object]] = []
    workload_offset = experiment_plan.workloads.index(workload)
    workload_seed = seed + workload_offset + 1

    for ratio in ratio_grid:
        base_events = generate_event_stream(
            workload,
            initial,
            rows=rows,
            cols=cols,
            update_count=updates,
            seed=workload_seed,
            query_every=0,
            matrix_entry_abs_bound=matrix_entry_abs_bound,
        )
        events = insert_queries_by_ratio(base_events, ratio)
        freshness_seconds = selected_freshness_seconds
        windows = list(
            publication_windows(
                events,
                initial,
                max_seconds=float(freshness_seconds),
                microbatch_max_updates=int(freshness["microbatch_max_updates"]),
                query_requires_latest=query_requires_latest,
            )
        )
        result = evaluate_causal_cell(
            windows=windows,
            initial_state=initial,
            base_config=base_config,
            split=split,
            candidates=candidates,
            costs=costs,
        )
        held_out = windows[result.tuning_end :]
        rho_id = rho_path_id(ratio)
        output_dir = args.output_dir / workload / freshness_path_id(freshness_seconds) / rho_id
        trace_sha256 = write_event_window_trace(
            output_dir / "event-window-trace.jsonl",
            windows=windows,
            workload=workload,
            freshness_seconds=freshness_seconds,
            ratio=ratio,
            experiment_plan_sha256=experiment_plan_sha256,
            manifest_sha256=manifest_sha256,
            seed=seed,
            workload_seed=workload_seed,
            rows=rows,
            cols=cols,
            initial_nnz_per_row=nnz_per_row,
            effective_slots=effective_slots,
            partition_rows=partition_rows,
            layout_measurement_kind=experiment_plan.layout_measurement_kind,
            initial_state_sha256=initial_state_sha256,
            microbatch_max_updates=int(freshness["microbatch_max_updates"]),
            query_requires_latest=query_requires_latest,
            split=split,
        )
        update_events_total = sum(event.kind == EventKind.SET for event in events)
        queries_total = sum(event.kind == EventKind.QUERY for event in events)
        metadata = {
            "workload": workload,
            "seed": workload_seed,
            "suite_seed": seed,
            "rows": rows,
            "cols": cols,
            "initial_nnz_per_row": nnz_per_row,
            "events_planned": updates,
            "effective_slots": effective_slots,
            "partition_rows": partition_rows,
            "layout_measurement_kind": experiment_plan.layout_measurement_kind,
            "freshness_seconds": float(freshness_seconds),
            "freshness_seconds_fraction": str(freshness_seconds),
            "queries_per_update_target": float(ratio),
            "queries_per_update_fraction": str(ratio),
            "rho_id": rho_id,
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
            "fixed_candidate_count": len(candidates),
            "selected_candidate_id": result.selected_candidate_id,
            "oracle_candidate_id": result.oracle_candidate_id,
            "span80_by_candidate": _candidate_span80(rows, candidates, result),
            "experiment_plan_sha256": experiment_plan_sha256,
            "manifest_sha256": manifest_sha256,
            "initial_state_sha256": initial_state_sha256,
            "event_window_trace_schema": EVENT_WINDOW_TRACE_SCHEMA,
            "event_window_trace_sha256": trace_sha256,
            "real_temporal_dataset": False,
            "state_model": CAUSAL_STATE_MODEL,
            "measurement_kind": CAUSAL_MEASUREMENT_KIND,
            "gate_eligible": False,
            "complete_cost_claim_allowed": False,
            "complete_reference_set": False,
        }
        records = _candidate_records(candidates, result)
        report_audit = {
            "tuning_results": {
                candidate_id: simulation.metrics
                for candidate_id, simulation in result.tuning_results.items()
            },
            "selected_candidate_id": result.selected_candidate_id,
            "oracle_candidate_id": result.oracle_candidate_id,
        }
        write_causal_records(output_dir, records, costs, metadata, **report_audit)
        write_causal_summary(output_dir, records, costs, metadata, **report_audit)
        write_causal_plots(output_dir, records, costs, **report_audit)
        write_checksums(output_dir)
        cells.append(
            {
                "relative_path": output_dir.relative_to(args.output_dir).as_posix(),
                "rho_id": rho_id,
                "rho_fraction": str(ratio),
                "event_window_trace_sha256": trace_sha256,
                "cell_checksums_sha256": _sha256_file(output_dir / "SHA256SUMS"),
            }
        )

    shard_status: dict[str, object] = {
        "schema": CAUSAL_SCHEMA,
        "state_model": CAUSAL_STATE_MODEL,
        "measurement_kind": CAUSAL_MEASUREMENT_KIND,
        "gate_eligible": False,
        "complete_cost_claim_allowed": False,
        "complete_reference_set": False,
        "suite_complete": False,
        "deferred_reference_baselines": list(DEFERRED_REFERENCE_BASELINES),
        "seed": seed,
        "experiment_plan_sha256": experiment_plan_sha256,
        "manifest_sha256": manifest_sha256,
        "experiment_plan_version": experiment_plan.plan_version,
        "workload": workload,
        "freshness_seconds": float(selected_freshness_seconds),
        "freshness_seconds_fraction": str(selected_freshness_seconds),
        "rho_ids": [rho_path_id(ratio) for ratio in ratio_grid],
        "cells_expected": len(ratio_grid),
        "cells_completed": len(cells),
        "candidate_ids": sorted(candidate.candidate_id for candidate in candidates),
        "effective_slots": effective_slots,
        "partition_rows": partition_rows,
        "layout_measurement_kind": experiment_plan.layout_measurement_kind,
        "planned_bandwidth_profiles_mbps": [
            float(value) for value in experiment_plan.bandwidth_profiles_mbps
        ],
        "deferred_unpriced_plan_dimensions": ["bandwidth_profiles_mbps"],
        "preflight": asdict(preflight_report),
        "cells": cells,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "SHARD_STATUS.json").write_text(
        json.dumps(shard_status, indent=2, sort_keys=True, allow_nan=False),
        encoding="utf-8",
    )
    write_checksums(args.output_dir)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default="config/params_manifest.json")
    parser.add_argument("--experiment-plan", default="config/experiment_plan.json")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--seed", type=parse_canonical_seed, required=True)
    parser.add_argument("--workload", required=True)
    parser.add_argument("--freshness-seconds", required=True)
    parser.add_argument("--rows", type=int)
    parser.add_argument("--cols", type=int)
    parser.add_argument("--nnz-per-row", type=int)
    parser.add_argument("--updates", type=int)
    parser.add_argument("--effective-slots", type=int)
    parser.add_argument("--partition-rows", type=int)
    return parser


def main() -> int:
    return run_suite(build_parser().parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
