#!/usr/bin/env python3
"""Thin CLI for the repository-owned publication acquisition transaction."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path

from dynamic_cssc.publication_acquisition import (
    AcquisitionBundle,
    acquire_publication_sources,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Fetch one repository-frozen publication corpus into a new external bundle. "
            "URLs, roles, headers, attribution, and evidence flags are not caller options."
        )
    )
    parser.add_argument("--dataset-id", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser


def _run(
    arguments: argparse.Namespace,
    *,
    acquirer: Callable[[str, Path], AcquisitionBundle],
) -> int:
    acquirer(arguments.dataset_id, arguments.output_dir)
    return 0


def _run_cli(
    argv: list[str],
    *,
    acquirer: Callable[[str, Path], AcquisitionBundle],
) -> int:
    return _run(_parser().parse_args(argv), acquirer=acquirer)


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    try:
        return _run(arguments, acquirer=acquire_publication_sources)
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
