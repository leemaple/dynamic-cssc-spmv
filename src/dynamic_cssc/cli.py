from __future__ import annotations

import argparse
import json
from pathlib import Path

from .events import publication_windows
from .manifest import load_manifest
from .metrics import UnitCosts
from .report import write_checksums, write_plots, write_records, write_summary
from .simulator import SimulationConfig, SimulationTarget, simulate_targets
from .span80 import span80_curve
from .strategy_state import STRATEGIES
from .workloads import generate_event_stream, generate_initial_matrix

SUPPORTED_WORKLOADS = (
    "zipf",
    "migrating-hotspot",
    "single-row-hotspot",
    "multi-row-hotspot",
    "bursty",
    "mixed-insert-delete-modify",
    "repeated-coordinate",
)


def _smoke(args: argparse.Namespace) -> int:
    if args.workload not in SUPPORTED_WORKLOADS:
        raise ValueError(f"unknown workload: {args.workload}")
    manifest = load_manifest(args.manifest)
    rows = args.rows
    cols = args.cols
    matrix_entry_abs_bound = int(
        manifest["integer_correctness"]["matrix_entry_abs_bound"]
    )
    initial = generate_initial_matrix(
        rows,
        cols,
        args.nnz_per_row,
        seed=args.seed,
        matrix_entry_abs_bound=matrix_entry_abs_bound,
    )
    events = generate_event_stream(
        args.workload,
        initial,
        rows=rows,
        cols=cols,
        update_count=args.updates,
        seed=args.seed + 1,
        query_every=args.query_every,
        matrix_entry_abs_bound=matrix_entry_abs_bound,
    )
    freshness = manifest["freshness"]
    windows = list(
        publication_windows(
            events,
            initial,
            max_seconds=float(freshness["max_seconds"]),
            microbatch_max_updates=int(freshness["microbatch_max_updates"]),
            query_requires_latest=bool(freshness["query_requires_latest"]),
        )
    )
    config = SimulationConfig(
        rows=rows,
        cols=cols,
        effective_slots=min(
            int(manifest["packing"]["effective_slots"]),
            args.effective_slots,
        ),
        partition_rows=args.partition_rows,
        matrix_value_bound=matrix_entry_abs_bound,
        max_row_nnz=int(manifest["matrix"]["max_nnz_per_row"]),
        reserved_slack_beta=args.slack_beta,
        periodic_repack_windows=args.periodic_repack_period,
        packed_coo_segment_capacity=args.coo_segment_capacity,
    )
    costs = UnitCosts()
    results = simulate_targets(
        windows,
        initial,
        [
            SimulationTarget(
                run_id=strategy,
                strategy=strategy,
                config=config,
            )
            for strategy in STRATEGIES
        ],
        measure_from=0,
    )
    metrics = sorted(
        (result.metrics for result in results.values()),
        key=lambda item: item.strategy,
    )

    aggregate_overflow = [0] * rows
    # PublicationWindow already carries the causal before/after state for each net update.
    for window in windows:
        for update in window.updates:
            if update.before == 0 and update.after != 0:
                aggregate_overflow[update.row] += 1

    output_dir = Path(args.output_dir)
    metadata = {
        "schema": "day1-smoke-predicted-v1",
        "measurement_kind": "predicted-proxy",
        "gate_eligible": False,
        "complete_cost_claim_allowed": False,
        "state_model": "persistent-strategy-snapshots",
        "seed": args.seed,
        "workload": args.workload,
        "windows": len(windows),
        "updates_requested": args.updates,
        "manifest": str(args.manifest),
        "span80": span80_curve(aggregate_overflow),
    }
    write_records(output_dir, metrics, costs, metadata)
    write_summary(output_dir, metrics, costs, metadata)
    write_plots(output_dir, metrics, costs)
    (output_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True, allow_nan=False), encoding="utf-8"
    )
    write_checksums(output_dir)
    print(output_dir / "SUMMARY.md")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dynamic-cssc")
    subparsers = parser.add_subparsers(dest="command", required=True)
    smoke = subparsers.add_parser("smoke", help="run a predicted-only synthetic smoke model")
    smoke.add_argument("--manifest", default="config/params_manifest.json")
    smoke.add_argument("--output-dir", required=True)
    smoke.add_argument("--seed", type=int, required=True)
    smoke.add_argument("--workload", choices=SUPPORTED_WORKLOADS, default="zipf")
    smoke.add_argument("--rows", type=int, default=128)
    smoke.add_argument("--cols", type=int, default=128)
    smoke.add_argument("--nnz-per-row", type=int, default=8)
    smoke.add_argument("--updates", type=int, default=512)
    smoke.add_argument("--query-every", type=int, default=32)
    smoke.add_argument("--effective-slots", type=int, default=1024)
    smoke.add_argument("--partition-rows", type=int, default=64)
    smoke.add_argument("--slack-beta", type=float, default=0.10)
    smoke.add_argument("--periodic-repack-period", type=int, default=4)
    smoke.add_argument("--coo-segment-capacity", type=int, default=64)
    smoke.set_defaults(handler=_smoke)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
