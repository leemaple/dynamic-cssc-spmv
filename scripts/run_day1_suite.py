#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from dynamic_cssc.events import publication_windows
from dynamic_cssc.manifest import load_manifest
from dynamic_cssc.metrics import UnitCosts
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default="config/params_manifest.json")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--rows", type=int, default=256)
    parser.add_argument("--cols", type=int, default=256)
    parser.add_argument("--nnz-per-row", type=int, default=8)
    parser.add_argument("--updates", type=int, default=2048)
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    initial = generate_initial_matrix(
        args.rows, args.cols, args.nnz_per_row, seed=args.seed
    )
    freshness = manifest["freshness"]
    costs = UnitCosts()
    top_summary = {
        "status": "synthetic-predicted-proxy-not-a-48h-gate-verdict",
        "seed": args.seed,
        "workloads": [],
    }

    for offset, workload in enumerate(WORKLOADS):
        events = generate_event_stream(
            workload,
            initial,
            rows=args.rows,
            cols=args.cols,
            update_count=args.updates,
            seed=args.seed + offset + 1,
            query_every=32,
        )
        windows = list(
            publication_windows(
                events,
                initial,
                max_seconds=float(freshness["max_seconds"]),
                microbatch_max_updates=int(freshness["microbatch_max_updates"]),
                query_requires_latest=True,
            )
        )
        warmup_end = int(len(windows) * 0.10)
        tuning_end = int(len(windows) * 0.40)
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

        output_dir = args.output_dir / workload
        metadata = {
            "status": "predicted-proxy-not-measured",
            "workload": workload,
            "seed": args.seed + offset + 1,
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
