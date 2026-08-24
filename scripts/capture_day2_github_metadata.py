#!/usr/bin/env python3
"""Capture provider metadata at the two formal Day 2 workflow boundaries."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from dynamic_cssc.day2_calibration_github import (  # noqa: E402
    capture_repository_day1a_github_metadata,
    capture_repository_day2_github_metadata,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture GitHub identities for the formal Day 2 evidence chain."
    )
    subparsers = parser.add_subparsers(dest="boundary", required=True)
    day1a = subparsers.add_parser("day1a-input")
    day1a.add_argument("--day1a-directory", required=True, type=Path)
    day1a.add_argument("--output", required=True, type=Path)
    day2 = subparsers.add_parser("day2-output")
    day2.add_argument("--archive", required=True, type=Path)
    day2.add_argument("--output", required=True, type=Path)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    if arguments.boundary == "day1a-input":
        output = capture_repository_day1a_github_metadata(
            arguments.day1a_directory,
            arguments.output,
        )
    elif arguments.boundary == "day2-output":
        output = capture_repository_day2_github_metadata(
            arguments.archive,
            arguments.output,
        )
    else:  # pragma: no cover - argparse owns the closed command set
        raise RuntimeError("unsupported metadata boundary")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
