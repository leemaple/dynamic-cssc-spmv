#!/usr/bin/env python3
"""Independently reinspect one Route A registration archive."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dynamic_cssc.route_a_lineage import (
    RouteALineageError,
    inspect_route_a_registration_archive,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--expected-s1", required=True)
    parser.add_argument("--archive", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        inspection = inspect_route_a_registration_archive(
            arguments.repository_root,
            arguments.expected_s1,
            arguments.archive.read_bytes(),
        )
    except (OSError, RouteALineageError) as error:
        print(f"Route A registration inspection failed: {error}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "archive_sha256": inspection.archive_sha256,
                "behavior_inventory_sha256": inspection.behavior_inventory_sha256,
                "formal_authority_granted": False,
                "registration_evidence_sha256": (inspection.registration_evidence_sha256),
                "repository_anchor_installed": False,
                "schema_version": "dynamic-cssc-route-a-registration-inspection-receipt-v1",
                "source_git_sha": inspection.source_git_sha,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
