#!/usr/bin/env python3
"""Bounded, disjoint R1 engineering sentinel. No formal matrix entry point."""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
from pathlib import Path

from dynamic_cssc.r1_native_lifecycle import (
    STRATEGIES,
    canonical,
    engineering_workload,
    run_engineering_trace,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--strategy", required=True, choices=STRATEGIES)
    parser.add_argument("--workload", choices=("handwritten", "calibration"), default="handwritten")
    parser.add_argument("--rows", type=int, choices=(256, 1024))
    parser.add_argument("--distribution", choices=("concentrated", "dispersed"))
    args = parser.parse_args()
    # Do not let rejected invocations write into a previous run's evidence.
    if args.output_dir.exists() or args.output_dir.is_symlink():
        parser.error("output directory already exists; prior receipts must remain untouched")
    if args.workload == "calibration":
        if args.rows is None or args.distribution is None:
            parser.error("calibration requires explicit rows and distribution")
        from dynamic_cssc.r1_workloads import calibration_workload

        workload = calibration_workload(
            rows=args.rows, distribution=args.distribution, queries_per_window=8
        )
    else:
        if args.rows is not None or args.distribution is not None:
            parser.error("handwritten fixture does not accept calibration factors")
        workload = engineering_workload()
    try:
        result = run_engineering_trace(
            workload, args.strategy, args.executable.resolve(), args.output_dir
        )
    except Exception as error:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        with (args.output_dir / "failure.json").open("xb") as failure:
            failure.write(
                canonical(
                    {
                        "evidence_class": "engineering-sentinel",
                        "formal_authority": False,
                        "status": "failed",
                        "error_type": type(error).__name__,
                        "error": str(error),
                    }
                )
            )
        raise
    result["environment"] = {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "source_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "omp_num_threads": 1,
        "openblas_num_threads": 1,
    }
    (args.output_dir / "summary.json").write_bytes(canonical(result))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
