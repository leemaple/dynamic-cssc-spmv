#!/usr/bin/env python3
"""Launch or enter the formal Day 2 isolated calibration worker."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from dynamic_cssc.day2_calibration_runtime import (  # noqa: E402
    _run_isolated_worker,
    run_day2_calibration_isolated,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the path-only formal Day 2 calibration launcher."
    )
    parser.add_argument("--day1a-directory", required=True, type=Path)
    parser.add_argument("--github-artifact-metadata", required=True, type=Path)
    parser.add_argument("--isolated-worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--execution-root", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--staging-archive", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--capability-fd", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--output-archive", type=Path)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    if arguments.isolated_worker:
        if (
            arguments.execution_root is None
            or arguments.staging_archive is None
            or arguments.capability_fd is None
            or arguments.output_archive is not None
        ):
            raise ValueError("isolated worker arguments are incomplete or mixed with public output")
        _run_isolated_worker(
            day1a_directory=arguments.day1a_directory,
            github_artifact_metadata_path=arguments.github_artifact_metadata,
            execution_root=arguments.execution_root,
            staging_archive=arguments.staging_archive,
            capability_fd=arguments.capability_fd,
        )
        return 0
    if (
        arguments.output_archive is None
        or arguments.execution_root is not None
        or arguments.staging_archive is not None
        or arguments.capability_fd is not None
    ):
        raise ValueError("public launcher requires exactly --output-archive")
    result = run_day2_calibration_isolated(
        arguments.day1a_directory,
        arguments.github_artifact_metadata,
        arguments.output_archive,
    )
    print(
        json.dumps(
            {
                "archive_bytes": result.archive_bytes,
                "archive_sha256": result.archive_sha256,
                "formal_authority_granted": result.formal_authority_granted,
                "output_archive": str(result.output_archive),
                "source_git_sha": result.source_git_sha,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
