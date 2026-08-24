#!/usr/bin/env python3
"""Identity-only CLI for the fail-closed publication statistics pipeline.

Cross-snapshot analysis remains HOLD until a closed Day1B bundle loader can
rehash and extract S2 plus the repository-owned Behavior Set inventory. This
entrypoint intentionally accepts no caller-authored compatibility receipt,
source SHA, inventory, or authority boolean.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from dynamic_cssc.publication_statistics import (
    canonical_json_bytes,
    write_publication_analysis_artifacts,
)

_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate canonical held-out unit records and emit the preregistered "
            "fixed-corpus publication analysis artifact."
        ),
        epilog=(
            "Cross-snapshot analysis is HOLD until a closed Day1B bundle loader "
            "rehashes and extracts compatibility inputs; this CLI is identity-only."
        ),
    )
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--input-sha256", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser


def _verified_payload(path: Path, claimed_sha256: str) -> object:
    if _LOWER_SHA256.fullmatch(claimed_sha256) is None:
        raise ValueError("--input-sha256 must be a lowercase SHA-256 digest")
    if not path.is_file():
        raise ValueError("--input must name an existing regular file")
    content = path.read_bytes()
    actual_sha256 = hashlib.sha256(content).hexdigest()
    if actual_sha256 != claimed_sha256:
        raise ValueError(
            f"input SHA-256 mismatch: expected {claimed_sha256}, observed {actual_sha256}"
        )
    try:
        payload = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("input is not a UTF-8 JSON document") from error
    if canonical_json_bytes(payload) != content:
        raise ValueError("input must use canonical JSON encoding with one trailing newline")
    return payload


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.output_dir.exists():
            raise ValueError("--output-dir must not already exist")
        payload = _verified_payload(args.input, args.input_sha256)
        artifact_sha256 = write_publication_analysis_artifacts(args.output_dir, payload)
    except (OSError, TypeError, ValueError) as error:
        print(f"publication analysis failed: {error}", file=sys.stderr)
        return 2
    receipt = {
        "schema_version": "dynamic-cssc-publication-analysis-cli-receipt-v1",
        "input_path": str(args.input.resolve()),
        "input_sha256": args.input_sha256,
        "output_dir": str(args.output_dir.resolve()),
        "artifact_sha256": artifact_sha256,
    }
    sys.stdout.buffer.write(canonical_json_bytes(receipt))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
