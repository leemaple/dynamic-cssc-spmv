#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass, replace
from fractions import Fraction
from itertools import chain, groupby
from math import isfinite
from pathlib import Path

from dynamic_cssc.day1_registry import (
    Day1CandidateCatalog,
    RegisteredCandidate,
    repository_day1_candidate_catalog,
)
from dynamic_cssc.events import Event, EventKind, PublicationWindow, publication_windows
from dynamic_cssc.manifest import load_manifest
from dynamic_cssc.metrics import StrategyMetrics, UnitCosts
from dynamic_cssc.preflight import run_day1_preflight
from dynamic_cssc.publication_traces import PublicationTransition
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
    simulate_strong_reference_causal,
    simulate_targets_causal,
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
DEFERRED_REFERENCE_BASELINES: tuple[str, ...] = ()
STRONG_REFERENCE_CANDIDATE_ID = "packed-coo-cloud-segmented-delta/segment-width=128"
_CANONICAL_SEED = re.compile(r"(?:0|[1-9][0-9]*)")
_MAX_SUITE_SEED = (1 << 63) - 1 - len(WORKLOADS)
_FROZEN_PLAN_LAYOUTS = {
    "0.2.0": (512, 512, 2048, 128),
    "0.3.0": (4096, 8193, 4096, 4096),
}

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


def _candidate_config(
    base_config: SimulationConfig,
    candidate: FixedCandidate | RegisteredCandidate,
) -> SimulationConfig:
    changes: dict[str, object] = {}
    if candidate.reserved_slack_beta is not None:
        changes["reserved_slack_beta"] = float(candidate.reserved_slack_beta)
    if candidate.periodic_repack_windows is not None:
        changes["periodic_repack_windows"] = candidate.periodic_repack_windows
    if candidate.packed_coo_segment_capacity is not None:
        changes["packed_coo_segment_capacity"] = candidate.packed_coo_segment_capacity
    return replace(base_config, **changes)


def _candidate_targets(
    base_config: SimulationConfig,
    candidates: tuple[RegisteredCandidate, ...],
) -> list[SimulationTarget]:
    return [
        SimulationTarget(
            run_id=candidate.candidate_id,
            strategy=candidate.strategy,
            config=_candidate_config(base_config, candidate),
        )
        for candidate in candidates
    ]


def _normalize_candidate_results(
    candidates: tuple[RegisteredCandidate, ...],
    results: dict[str, SimulationResult],
) -> dict[str, SimulationResult]:
    expected_ids = {candidate.candidate_id for candidate in candidates}
    actual_ids = set(results)
    if actual_ids != expected_ids:
        raise ValueError(
            "simulation result IDs must exactly match fixed candidate IDs; "
            f"missing={sorted(expected_ids - actual_ids)}, "
            f"extra={sorted(actual_ids - expected_ids)}"
        )
    normalized: dict[str, SimulationResult] = {}
    for candidate in candidates:
        result = results[candidate.candidate_id]
        if not isinstance(result, SimulationResult):
            raise TypeError("simulation results must be SimulationResult values")
        if result.metrics.strategy != candidate.strategy:
            raise ValueError(f"simulation result strategy contradicts {candidate.candidate_id}")
        normalized[candidate.candidate_id] = replace(
            result,
            metrics=replace(result.metrics, category=candidate.role),
        )
    return normalized


def _assemble_causal_cell(
    *,
    warmup_end: int,
    tuning_end: int,
    tuning_results: dict[str, SimulationResult],
    fixed_results: dict[str, SimulationResult],
    selection_candidates: tuple[FixedCandidate, ...],
    costs: UnitCosts,
) -> CausalCellResult:
    tuning_metrics = {
        candidate_id: result.metrics for candidate_id, result in tuning_results.items()
    }
    selected = select_tuned_fixed_candidate(selection_candidates, tuning_metrics, costs)
    fixed_metrics = {candidate_id: result.metrics for candidate_id, result in fixed_results.items()}
    selected_metric = fixed_metrics[selected.candidate_id]
    tuned_policy = replace(
        selected_metric,
        strategy="TunedFixedPolicy",
        category="tuned-fixed-policy",
        source="tuning-prefix-frozen",
    )
    selection_ids = {candidate.candidate_id for candidate in selection_candidates}
    ranked_oracle = [
        (metric.predicted_time(costs), candidate_id)
        for candidate_id, metric in fixed_metrics.items()
        if candidate_id in selection_ids
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


def _evaluate_causal_cell(
    *,
    windows: list[PublicationWindow],
    initial_state: dict[tuple[int, int], int],
    base_config: SimulationConfig,
    split: ExperimentSplit,
    costs: UnitCosts,
    catalog: Day1CandidateCatalog,
    simulate_targets_fn: Callable[..., dict[str, SimulationResult]],
    simulate_strong_fn: Callable[..., SimulationResult],
) -> CausalCellResult:
    """Exercise the private simulator seam under an already-admitted catalog."""

    if type(catalog) is not Day1CandidateCatalog:
        raise TypeError("catalog must be an exact Day1CandidateCatalog")
    warmup_end, tuning_end = split_boundaries(len(windows), split)
    strong_candidates = tuple(
        candidate
        for candidate in catalog.candidates
        if candidate.candidate_id == STRONG_REFERENCE_CANDIDATE_ID
    )
    if len(strong_candidates) != 1 or strong_candidates[0].role != "reference":
        raise ValueError("catalog must contain exactly one selectable strong reference")
    strong_candidate = strong_candidates[0]
    tuning_ordinary = tuple(
        candidate
        for candidate in catalog.selection_candidates
        if candidate.candidate_id != STRONG_REFERENCE_CANDIDATE_ID
    )
    held_out_ordinary = tuple(
        candidate
        for candidate in catalog.candidates
        if candidate.candidate_id != STRONG_REFERENCE_CANDIDATE_ID
    )

    ordinary_all_tuning_results, ordinary_fixed_results = simulate_targets_fn(
        windows,
        initial_state,
        _candidate_targets(base_config, held_out_ordinary),
        warmup_end=warmup_end,
        tuning_end=tuning_end,
    )
    ordinary_tuning_results = {
        candidate.candidate_id: ordinary_all_tuning_results[candidate.candidate_id]
        for candidate in tuning_ordinary
    }
    ordinary_tuning_results = _normalize_candidate_results(
        tuning_ordinary,
        ordinary_tuning_results,
    )
    strong_tuning_result, strong_fixed_result = simulate_strong_fn(
        windows,
        initial_state,
        _candidate_config(base_config, strong_candidate),
        warmup_end=warmup_end,
        tuning_end=tuning_end,
    )
    strong_tuning = _normalize_candidate_results(
        (strong_candidate,),
        {strong_candidate.candidate_id: strong_tuning_result},
    )
    tuning_results = {**ordinary_tuning_results, **strong_tuning}
    selection_candidates = tuple(
        FixedCandidate(
            candidate_id=candidate.candidate_id,
            strategy=candidate.strategy,
            reserved_slack_beta=candidate.reserved_slack_beta,
            periodic_repack_windows=candidate.periodic_repack_windows,
            packed_coo_segment_capacity=candidate.packed_coo_segment_capacity,
        )
        for candidate in catalog.selection_candidates
    )
    ordinary_fixed_results = _normalize_candidate_results(
        held_out_ordinary,
        ordinary_fixed_results,
    )
    strong_fixed = _normalize_candidate_results(
        (strong_candidate,),
        {strong_candidate.candidate_id: strong_fixed_result},
    )
    fixed_results = {**ordinary_fixed_results, **strong_fixed}
    return _assemble_causal_cell(
        warmup_end=warmup_end,
        tuning_end=tuning_end,
        tuning_results=tuning_results,
        fixed_results=fixed_results,
        selection_candidates=selection_candidates,
        costs=costs,
    )


def evaluate_causal_cell(
    *,
    windows: list[PublicationWindow],
    initial_state: dict[tuple[int, int], int],
    base_config: SimulationConfig,
    split: ExperimentSplit,
    costs: UnitCosts,
) -> CausalCellResult:
    """Tune references, freeze one, then separately replay all held-out roles."""

    catalog = repository_day1_candidate_catalog()
    return _evaluate_causal_cell(
        windows=windows,
        initial_state=initial_state,
        base_config=base_config,
        split=split,
        costs=costs,
        catalog=catalog,
        simulate_targets_fn=simulate_targets_causal,
        simulate_strong_fn=simulate_strong_reference_causal,
    )


_QUERY_LINEAR_METRIC_FIELDS = (
    "queries",
    "query_ciphertexts",
    "result_ciphertexts",
    "cc_multiplications",
    "relinearizations",
    "rotations",
    "additions",
    "plaintext_masks",
    "blinding_mask_ciphertexts",
    "blinding_dummy_ciphertexts",
    "blinding_encryptions",
    "blinding_additions",
    "decryptions",
    "client_merges",
    "mask_random_elements",
    "mask_mapped_elements",
    "client_reorder_elements",
)


def _query_scaled_windows(
    unit_windows: list[PublicationWindow],
    scaled_windows: list[PublicationWindow],
    multiplier: int,
) -> bool:
    if type(multiplier) is not int or multiplier < 1:
        raise ValueError("query multiplier must be a positive strict integer")
    return len(unit_windows) == len(scaled_windows) and all(
        replace(unit, query_count=unit.query_count * multiplier) == scaled
        for unit, scaled in zip(unit_windows, scaled_windows, strict=True)
    )


def _scale_simulation_queries(
    result: SimulationResult,
    multiplier: int,
) -> SimulationResult:
    if type(multiplier) is not int or multiplier < 1:
        raise ValueError("query multiplier must be a positive strict integer")
    metrics = replace(
        result.metrics,
        **{
            field: getattr(result.metrics, field) * multiplier
            for field in _QUERY_LINEAR_METRIC_FIELDS
        },
    )
    inventory = result.rotation_inventory
    return SimulationResult(
        metrics=metrics,
        overflow_by_row=dict(result.overflow_by_row),
        rotation_inventory=replace(
            inventory,
            measured_counts_by_exact_index=tuple(
                (index, count * multiplier)
                for index, count in inventory.measured_counts_by_exact_index
            ),
        ),
    )


def _rescale_causal_cell_queries(
    result: CausalCellResult,
    multiplier: int,
    costs: UnitCosts,
) -> CausalCellResult:
    tuning_results = {
        candidate_id: _scale_simulation_queries(simulation, multiplier)
        for candidate_id, simulation in result.tuning_results.items()
    }
    fixed_results = {
        candidate_id: _scale_simulation_queries(simulation, multiplier)
        for candidate_id, simulation in result.fixed_results.items()
    }
    selection_candidates = tuple(
        FixedCandidate(candidate_id, simulation.metrics.strategy)  # type: ignore[arg-type]
        for candidate_id, simulation in sorted(tuning_results.items())
    )
    return _assemble_causal_cell(
        warmup_end=result.warmup_end,
        tuning_end=result.tuning_end,
        tuning_results=tuning_results,
        fixed_results=fixed_results,
        selection_candidates=selection_candidates,
        costs=costs,
    )


def insert_queries_by_ratio(
    events: Iterable[Event | PublicationTransition],
    queries_per_update: Fraction | int | float | str,
) -> list[Event]:
    """Insert queries after complete accepted-event groups using exact rational rho.

    Legacy synthetic ``Event`` input keeps its one-SET-per-denominator-event contract.
    Publication input is a contiguous prefix from accepted ordinal zero: all transitions
    for one ordinal are emitted before its clock tick and queries. Every accepted group emits
    one TICK, so clipped no-ops advance freshness and rho without emitting a SET. After ``N``
    accepted events the cumulative query count is ``floor(N*rho)``.
    """

    ratio = (
        queries_per_update
        if isinstance(queries_per_update, Fraction)
        else Fraction(str(queries_per_update))
    )
    if ratio < 0:
        raise ValueError("queries_per_update must be nonnegative")

    event_iterator = iter(events)
    try:
        first = next(event_iterator)
    except StopIteration:
        return []

    scheduled: list[Event] = []
    if isinstance(first, Event):
        remainder = 0
        for event in chain((first,), event_iterator):
            if not isinstance(event, Event):
                raise TypeError("query scheduling inputs must not mix event representations")
            if event.kind == EventKind.QUERY:
                raise ValueError("base events must not contain queries")
            scheduled.append(event)
            if event.kind != EventKind.SET:
                continue
            remainder += ratio.numerator
            query_count, remainder = divmod(remainder, ratio.denominator)
            scheduled.extend(Event.query(event.timestamp) for _ in range(query_count))
        return scheduled

    if not isinstance(first, PublicationTransition):
        raise TypeError("query scheduling inputs must be events or publication transitions")
    logical_time_denominator: int | None = None
    transitions = chain((first,), event_iterator)
    for expected_accepted_ordinal, (accepted_ordinal, accepted_group_iterator) in enumerate(
        groupby(
            transitions,
            key=lambda transition: transition.accepted_event_ordinal,
        )
    ):
        accepted_group = tuple(accepted_group_iterator)
        if not all(isinstance(transition, PublicationTransition) for transition in accepted_group):
            raise TypeError("query scheduling inputs must not mix event representations")
        if accepted_ordinal != expected_accepted_ordinal:
            raise ValueError("publication accepted-event ordinals must be contiguous from zero")
        if any(
            type(transition.logical_time_numerator) is not int
            or transition.logical_time_numerator != accepted_ordinal
            for transition in accepted_group
        ):
            raise ValueError("publication logical time must equal accepted-event ordinal")
        group_denominators = {transition.logical_time_denominator for transition in accepted_group}
        if len(group_denominators) != 1 or any(
            type(value) is not int or value <= 0 for value in group_denominators
        ):
            raise ValueError("publication logical time must use one positive integer clock")
        group_denominator = next(iter(group_denominators))
        if logical_time_denominator is None:
            logical_time_denominator = group_denominator
        elif group_denominator != logical_time_denominator:
            raise ValueError("publication logical time must use one fixed clock")
        semantics = {transition.semantics for transition in accepted_group}
        transition_order = tuple(
            (transition.transition_ordinal, transition.transition_cause)
            for transition in accepted_group
        )
        if semantics == {"T1"}:
            if transition_order != ((0, "admission"),):
                raise ValueError("T1 transitions must contain exactly one admission")
        elif semantics == {"T2"}:
            if transition_order not in (
                ((1, "admission"),),
                ((0, "expiry"), (1, "admission")),
            ):
                raise ValueError("T2 transitions must order expiry before admission")
        else:
            raise ValueError("one publication transition group must use one T1 or T2 semantics")
        timestamp_fraction = Fraction(
            accepted_ordinal,
            group_denominator,
        )
        timestamp = float(timestamp_fraction)
        scheduled.extend(
            Event.set(timestamp, transition.row_index, transition.column_index, transition.after)
            for transition in accepted_group
            if transition.operation != "clipped-no-op"
        )
        scheduled.append(Event.tick(timestamp))
        queries_before = accepted_ordinal * ratio.numerator // ratio.denominator
        queries_after = (accepted_ordinal + 1) * ratio.numerator // ratio.denominator
        scheduled.extend(Event.query(timestamp) for _ in range(queries_after - queries_before))
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
    if plan_version not in _FROZEN_PLAN_LAYOUTS:
        raise ValueError("plan_version must equal a frozen value: 0.2.0 or 0.3.0")
    expected_rows, expected_cols, expected_effective_slots, expected_partition_rows = (
        _FROZEN_PLAN_LAYOUTS[plan_version]
    )

    split_payload = _mapping(payload["split"], "split")
    _require_exact_keys(split_payload, SPLIT_KEYS, "split")
    split = parse_experiment_split(split_payload)

    synthetic = _mapping(payload["synthetic"], "synthetic")
    _require_exact_keys(synthetic, SYNTHETIC_KEYS, "synthetic")
    rows = _strict_int(synthetic["rows"], "synthetic.rows", minimum=1)
    if rows != expected_rows:
        raise ValueError(
            f"synthetic.rows must equal the frozen value {expected_rows} for plan {plan_version}"
        )
    cols = _strict_int(synthetic["cols"], "synthetic.cols", minimum=1)
    if cols != expected_cols:
        raise ValueError(
            f"synthetic.cols must equal the frozen value {expected_cols} for plan {plan_version}"
        )
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
    if effective_slots != expected_effective_slots:
        raise ValueError(
            "synthetic.effective_slots must equal the frozen value "
            f"{expected_effective_slots} for plan {plan_version}"
        )
    partition_rows = _strict_int(synthetic["partition_rows"], "synthetic.partition_rows", minimum=1)
    if partition_rows != expected_partition_rows:
        raise ValueError(
            "synthetic.partition_rows must equal the frozen value "
            f"{expected_partition_rows} for plan {plan_version}"
        )
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


def _candidate_records(result: CausalCellResult) -> list[CausalMetricRecord]:
    records = [
        CausalMetricRecord(
            record_kind="fixed-candidate",
            candidate_id=candidate_id,
            label=candidate_id,
            strategy_kind=simulation.metrics.strategy,
            selection_source="fixed-candidate",
            metrics=simulation.metrics,
            candidate_role=simulation.metrics.category,
            rotation_inventory=simulation.rotation_inventory,
        )
        for candidate_id, simulation in sorted(result.fixed_results.items())
    ]
    selected_basis = result.fixed_results[result.selected_candidate_id]
    oracle_basis = result.fixed_results[result.oracle_candidate_id]
    records.extend(
        [
            CausalMetricRecord(
                record_kind="tuned-fixed-policy",
                candidate_id=result.selected_candidate_id,
                label="TunedFixedPolicy",
                strategy_kind=selected_basis.metrics.strategy,
                selection_source="tuning-prefix-only",
                metrics=result.tuned_policy,
                candidate_role="reference",
                rotation_inventory=selected_basis.rotation_inventory,
            ),
            CausalMetricRecord(
                record_kind="diagnostic-oracle",
                candidate_id=result.oracle_candidate_id,
                label="BestFixed-Offline-Oracle",
                strategy_kind=oracle_basis.metrics.strategy,
                selection_source="held-out-hindsight-diagnostic-only",
                metrics=result.offline_oracle,
                candidate_role="reference",
                rotation_inventory=oracle_basis.rotation_inventory,
            ),
        ]
    )
    return records


def _candidate_span80(
    rows: int,
    result: CausalCellResult,
) -> dict[str, dict[int, float]]:
    curves: dict[str, dict[int, float]] = {}
    for candidate_id, simulation in sorted(result.fixed_results.items()):
        overflow_by_row = simulation.overflow_by_row
        for row, count in overflow_by_row.items():
            if (
                isinstance(row, bool)
                or not isinstance(row, int)
                or not 0 <= row < rows
                or isinstance(count, bool)
                or not isinstance(count, int)
                or count < 0
            ):
                raise ValueError(f"invalid measured overflow_by_row for {candidate_id}")
        curves[candidate_id] = span80_curve([overflow_by_row.get(row, 0) for row in range(rows)])
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
    fixed_candidate_ids: tuple[str, ...] | None = None
    reference_candidate_ids: tuple[str, ...] | None = None
    ablation_candidate_ids: tuple[str, ...] | None = None
    workload_offset = experiment_plan.workloads.index(workload)
    workload_seed = seed + workload_offset + 1
    unit_ratio_windows: list[PublicationWindow] | None = None
    unit_ratio_result: CausalCellResult | None = None

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
        evaluation_mode = "full-state-replay"
        query_scaling_source_rho: str | None = None
        if (
            ratio.denominator == 1
            and ratio > 1
            and unit_ratio_windows is not None
            and unit_ratio_result is not None
        ):
            multiplier = ratio.numerator
            if not _query_scaled_windows(unit_ratio_windows, windows, multiplier):
                raise ValueError(
                    "integer-rho query scaling requires an exact rho=1 window trajectory"
                )
            result = _rescale_causal_cell_queries(unit_ratio_result, multiplier, costs)
            evaluation_mode = "exact-query-linearity-from-rho-1"
            query_scaling_source_rho = "1"
        else:
            result = evaluate_causal_cell(
                windows=windows,
                initial_state=initial,
                base_config=base_config,
                split=split,
                costs=costs,
            )
            if ratio == 1:
                unit_ratio_windows = windows
                unit_ratio_result = result
        cell_fixed_candidate_ids = tuple(sorted(result.fixed_results))
        cell_reference_candidate_ids = tuple(sorted(result.tuning_results))
        cell_ablation_candidate_ids = tuple(
            sorted(set(cell_fixed_candidate_ids) - set(cell_reference_candidate_ids))
        )
        if not (
            len(cell_fixed_candidate_ids) == 14
            and len(cell_reference_candidate_ids) == 13
            and cell_ablation_candidate_ids == ("packed-coo-client-lane-delta/capacity=128",)
            and result.selected_candidate_id in cell_reference_candidate_ids
            and result.oracle_candidate_id in cell_reference_candidate_ids
        ):
            raise ValueError("cell result does not satisfy the canonical 14/13/1 role contract")
        if fixed_candidate_ids is None:
            fixed_candidate_ids = cell_fixed_candidate_ids
            reference_candidate_ids = cell_reference_candidate_ids
            ablation_candidate_ids = cell_ablation_candidate_ids
        elif (
            cell_fixed_candidate_ids != fixed_candidate_ids
            or cell_reference_candidate_ids != reference_candidate_ids
            or cell_ablation_candidate_ids != ablation_candidate_ids
        ):
            raise ValueError("candidate role IDs changed between cells in one shard")
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
            "causal_evaluation_mode": evaluation_mode,
            "query_scaling_source_rho_fraction": query_scaling_source_rho,
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
            "span80_by_candidate": _candidate_span80(rows, result),
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
            "security_claim_allowed": False,
            "formal_performance_claim": False,
            "complete_reference_set": True,
        }
        records = _candidate_records(result)
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
                "causal_evaluation_mode": evaluation_mode,
                "query_scaling_source_rho_fraction": query_scaling_source_rho,
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
        "security_claim_allowed": False,
        "formal_performance_claim": False,
        "complete_reference_set": True,
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
        "candidate_ids": list(fixed_candidate_ids or ()),
        "reference_candidate_ids": list(reference_candidate_ids or ()),
        "ablation_candidate_ids": list(ablation_candidate_ids or ()),
        "fixed_candidate_count": len(fixed_candidate_ids or ()),
        "reference_candidate_count": len(reference_candidate_ids or ()),
        "ablation_candidate_count": len(ablation_candidate_ids or ()),
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
