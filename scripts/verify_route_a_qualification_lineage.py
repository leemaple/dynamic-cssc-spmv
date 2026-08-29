#!/usr/bin/env python3
"""Verify the exact S1/S2 Route A compatibility receipt for one workflow job."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dynamic_cssc.route_a_lineage import (
    RouteALineageError,
    verify_route_a_s1_s2_compatibility,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--s1", required=True)
    parser.add_argument("--s2", required=True)
    parser.add_argument("--expected-receipt-sha256", required=True)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        if not arguments.repository_root.is_absolute():
            raise RouteALineageError("qualification repository root must be absolute")
        receipt = verify_route_a_s1_s2_compatibility(
            arguments.repository_root,
            s1=arguments.s1,
            s2=arguments.s2,
        )
        if receipt.sha256 != arguments.expected_receipt_sha256:
            raise RouteALineageError("qualification compatibility receipt address changed")
        print(
            json.dumps(
                {
                    "compatibility_receipt_sha256": receipt.sha256,
                    "formal_authority_granted": False,
                    "s1": arguments.s1,
                    "s2": arguments.s2,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except (OSError, RouteALineageError, TypeError, ValueError) as error:
        print(f"Route A qualification lineage failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
