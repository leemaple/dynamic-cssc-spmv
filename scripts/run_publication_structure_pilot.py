#!/usr/bin/env python3
"""Run the repository-owned outcome-blind publication structure pilot."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path

from dynamic_cssc.publication_structure_pilot import (
    PublicationStructurePilotBundle,
    produce_publication_structure_pilot,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Inspect the frozen external acquisition bundles through the fixed, "
            "permanently non-admissible structure-pilot contract."
        )
    )
    parser.add_argument("--acquisition-bundle-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser


def _run(
    arguments: argparse.Namespace,
    *,
    producer: Callable[[Path, Path], PublicationStructurePilotBundle],
) -> int:
    producer(arguments.acquisition_bundle_root, arguments.output_dir)
    return 0


def _run_cli(
    argv: list[str],
    *,
    producer: Callable[[Path, Path], PublicationStructurePilotBundle],
) -> int:
    return _run(_parser().parse_args(argv), producer=producer)


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    try:
        return _run(arguments, producer=produce_publication_structure_pilot)
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
