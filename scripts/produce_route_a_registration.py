#!/usr/bin/env python3
"""Produce one non-authorizing Route A descriptive registration archive."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from dynamic_cssc.route_a_lineage import (
    RouteALineageError,
    produce_route_a_registration_archive,
)


def _write_new_atomic(path: Path, content: bytes) -> None:
    path = path.resolve(strict=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise RouteALineageError("registration output path already exists")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o600)
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--expected-s1", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        registration = produce_route_a_registration_archive(
            arguments.repository_root, arguments.expected_s1
        )
        _write_new_atomic(arguments.output, registration.archive_bytes)
    except (OSError, RouteALineageError) as error:
        print(f"Route A registration production failed: {error}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "archive_sha256": registration.archive_sha256,
                "behavior_inventory_sha256": registration.behavior_inventory_sha256,
                "formal_authority_granted": False,
                "registration_evidence_sha256": (registration.registration_evidence_sha256),
                "repository_anchor_installed": False,
                "schema_version": "dynamic-cssc-route-a-registration-producer-receipt-v1",
                "source_git_sha": registration.source_git_sha,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
