#!/usr/bin/env python3
"""Independently reinspect a follow-up registration archive."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from dynamic_cssc.followup_performance_lineage import (
    FollowupLineageError,
    inspect_followup_registration_archive,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--s1", required=True)
    parser.add_argument("--s2", required=True)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--expected-archive-sha256", required=True)
    parser.add_argument("--expected-envelope-sha256", required=True)
    arguments = parser.parse_args()
    try:
        if not arguments.repository_root.is_absolute() or not arguments.archive.is_absolute():
            raise FollowupLineageError("follow-up verification paths must be absolute")
        inspection = inspect_followup_registration_archive(
            arguments.repository_root,
            s1=arguments.s1,
            s2=arguments.s2,
            archive_bytes=arguments.archive.read_bytes(),
        )
        if (
            inspection.archive_sha256 != arguments.expected_archive_sha256
            or inspection.envelope.sha256 != arguments.expected_envelope_sha256
        ):
            raise FollowupLineageError("follow-up registration address changed")
        print(
            json.dumps(
                {
                    "archive_sha256": inspection.archive_sha256,
                    "artifact_name": inspection.artifact_name,
                    "authority": False,
                    "compatibility_receipt_sha256": (
                        inspection.compatibility_receipt_sha256
                    ),
                    "envelope_sha256": inspection.envelope.sha256,
                    "formal_execution_authorized": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        print(f"follow-up registration verification failed closed: {error}", file=os.sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
