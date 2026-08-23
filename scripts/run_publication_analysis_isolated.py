#!/usr/bin/env python3
"""Invoke the closed publication runtime-isolation boundary."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dynamic_cssc.publication_runtime import (
    PublicationRuntimeError,
    run_publication_analysis_isolated,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the frozen publication analyzer in an isolated detached S3 checkout."
    )
    parser.add_argument("--input-artifact", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        receipt = run_publication_analysis_isolated(
            args.input_artifact.absolute(),
            args.output_directory.absolute(),
        )
    except (OSError, PublicationRuntimeError) as error:
        print(f"publication runtime isolation failed: {error}", file=sys.stderr)
        return 2
    document = {
        "formal_authority_granted": receipt.formal_authority_granted,
        "output_directory": str(receipt.output_directory),
        "receipt_sha256": receipt.receipt_sha256,
        "schema_version": "dynamic-cssc-publication-runtime-launcher-cli-receipt-v1",
    }
    sys.stdout.write(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
