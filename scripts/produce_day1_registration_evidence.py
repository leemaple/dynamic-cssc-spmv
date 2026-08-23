#!/usr/bin/env python3
"""Produce a closed, descriptive Day-1 registration evidence archive."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dynamic_cssc.day1_registration_evidence import (
    Day1RegistrationEvidenceError,
    Day1RegistrationEvidenceHold,
    produce_day1_registration_evidence_archive,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Produce repository-bound Day-1 composite registration evidence. "
            "The archive is descriptive and cannot register candidates."
        )
    )
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        archive = produce_day1_registration_evidence_archive(arguments.output_dir)
    except (Day1RegistrationEvidenceError, Day1RegistrationEvidenceHold, OSError) as error:
        print(f"Day-1 registration evidence production failed: {error}", file=sys.stderr)
        return 2
    receipt = {
        "archive_dir": str(archive.output_dir.resolve()),
        "manifest_sha256": archive.manifest_sha256,
        "registration_evidence_sha256": archive.registration_evidence_sha256,
        "schema_version": "dynamic-cssc-day1-registration-evidence-cli-receipt-v1",
    }
    sys.stdout.write(
        json.dumps(
            receipt,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
