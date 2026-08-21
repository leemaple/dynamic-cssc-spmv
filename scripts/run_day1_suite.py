#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections.abc import Iterable
from dataclasses import asdict
from fractions import Fraction
from pathlib import Path

from dynamic_cssc.events import Event, EventKind, publication_windows
from dynamic_cssc.manifest import load_manifest
from dynamic_cssc.metrics import UnitCosts
from dynamic_cssc.preflight import run_day1_preflight
from dynamic_cssc.report import write_checksums, write_plots, write_records, write_summary
from dynamic_cssc.simulator import SimulationConfig, simulate
from dynamic_cssc.span80 import span80_curve
from dynamic_cssc.workloads import generate_event_stream, generate_initial_matrix

WORKLOADS = (
    "zipf",
    "migrating-hotspot",
    "single-row-hotspot",
    "multi-row-hotspot",
    "bursty",
    "mixed-insert-delete-modify",
    "repeated-coordinate",
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


def _ratio_label(ratio: Fraction) -> str:
    if ratio.denominator == 1:
        return str(ratio.numerator)
    return format(float(ratio), ".12g").replace(".", "p")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default="config/params_manifest.json")
    parser.add_argument("--experiment-plan", default="config/experiment_plan.json")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--rows", type=int, default=256)
    parser.add_argument("--cols", type=int, default=256)
    parser.add_argument("--nnz-per-row", type=int, default=8)
    parser.add_argument("--updates", type=int, default=2048)
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    preflight_report = run_day1_preflight(manifest)
    experiment_plan = json.loads(Path(args.experiment_plan).read_text(encoding="utf-8"))
    split = experiment_plan["split"]
    warmup_fraction = float(split["warmup"])
    tuning_fraction = float(split["tuning"])
    held_out_fraction = float(split["held_out"])
    if abs(warmup_fraction + tuning_fraction + held_out_fraction - 1.0) > 1e-9:
        raise ValueError("experiment split fractions must sum to one")
    ratio_grid = [
        Fraction(str(value))
        for value in experiment_plan["synthetic"]["queries_per_update_grid"]
    ]
    if not ratio_grid:
        raise ValueError("queries_per_update_grid must not be empty")
    matrix_entry_abs_bound = int(
        manifest["integer_correctness"]["matrix_entry_abs_bound"]
    )
    initial = generate_initial_matrix(
        args.rows,
        args.cols,
        args.nnz_per_row,
        seed=args.seed,
        matrix_entry_abs_bound=matrix_entry_abs_bound,
    )
    freshness = manifest["freshness"]
    costs = UnitCosts()
    top_summary = {
        "status": "synthetic-predicted-proxy-not-a-48h-gate-verdict",
        "seed": args.seed,
        "experiment_plan": str(args.experiment_plan),
        "preflight": asdict(preflight_report),
        "workloads": [],
    }

    for offset, workload in enumerate(WORKLOADS):
        for ratio in ratio_grid:
            base_events = generate_event_stream(
                workload,
                initial,
                rows=args.rows,
                cols=args.cols,
                update_count=args.updates,
                seed=args.seed + offset + 1,
                query_every=0,
                matrix_entry_abs_bound=matrix_entry_abs_bound,
            )
            events = insert_queries_by_ratio(base_events, ratio)
            windows = list(
                publication_windows(
                    events,
                    initial,
                    max_seconds=float(freshness["max_seconds"]),
                    microbatch_max_updates=int(freshness["microbatch_max_updates"]),
                    query_requires_latest=True,
                )
            )
            warmup_end = int(len(windows) * warmup_fraction)
            tuning_end = int(len(windows) * (warmup_fraction + tuning_fraction))
            held_out = windows[tuning_end:]
            config = SimulationConfig(
                rows=args.rows,
                effective_slots=min(int(manifest["packing"]["effective_slots"]), 2048),
                partition_rows=128,
            )
            metrics = simulate(held_out, initial, config, costs=costs)
            overflow = [0] * args.rows
            for window in held_out:
                for update in window.updates:
                    if initial.get((update.row, update.col), 0) == 0 and update.after != 0:
                        overflow[update.row] += 1

            output_dir = args.output_dir / workload / f"rho-{_ratio_label(ratio)}"
            update_events_total = sum(
                event.kind == EventKind.SET for event in events
            )
            queries_total = sum(event.kind == EventKind.QUERY for event in events)
            metadata = {
                "status": "predicted-proxy-not-measured",
                "workload": workload,
                "seed": args.seed + offset + 1,
                "queries_per_update_target": float(ratio),
                "queries_per_update_scheduled": (
                    queries_total / update_events_total if update_events_total else 0.0
                ),
                "update_events_total": update_events_total,
                "queries_total": queries_total,
                "held_out_queries": sum(window.query_count for window in held_out),
                "windows": len(held_out),
                "windows_total": len(windows),
                "warmup_windows": warmup_end,
                "tuning_windows": max(0, tuning_end - warmup_end),
                "held_out_windows": len(held_out),
                "span80": span80_curve(overflow),
                "real_temporal_dataset": False,
                "gate_eligible": False,
            }
            write_records(output_dir, metrics, costs, metadata)
            write_summary(output_dir, metrics, costs, metadata)
            write_plots(output_dir, metrics, costs)
            write_checksums(output_dir)
            top_summary["workloads"].append(metadata)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "SUITE_STATUS.json").write_text(
        json.dumps(top_summary, indent=2, sort_keys=True), encoding="utf-8"
    )
    write_checksums(args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
