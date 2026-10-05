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
    args = parser.parse_args()
    try:
        result = run_engineering_trace(
            engineering_workload(), args.strategy, args.executable.resolve(), args.output_dir
        )
    except Exception as error:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "failure.json").write_bytes(
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
