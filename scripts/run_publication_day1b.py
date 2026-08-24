#!/usr/bin/env python3
"""Produce one closed publication Day1B unit through the two-path public seam."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dynamic_cssc.publication_day1b import (
    PublicationDay1BHold,
    produce_publication_day1b_unit,
)
from dynamic_cssc.publication_statistics import canonical_json_bytes


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Produce one exact 18-cell publication Day1B unit.",
    )
    parser.add_argument("--trace-bundle-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        bundle = produce_publication_day1b_unit(args.trace_bundle_dir, args.output_dir)
    except (OSError, TypeError, ValueError, PublicationDay1BHold) as error:
        print(f"publication Day1B unit failed: {error}", file=sys.stderr)
        return 2
    receipt = {
        "schema_version": "dynamic-cssc-publication-day1b-cli-receipt-v1",
        "output_dir": str(bundle.output_dir.resolve()),
        "manifest_sha256": bundle.manifest_sha256,
        "heldout_input_member_sha256": bundle.heldout_fragment_sha256,
        "schedule_sha256": bundle.schedule_sha256,
        "serialization_ledger_sha256": bundle.serialization_ledger_sha256,
        "checksums_sha256": bundle.checksums_sha256,
    }
    sys.stdout.buffer.write(canonical_json_bytes(receipt))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
