#!/usr/bin/env python3
"""Produce the deterministic, authority-false follow-up registration archive."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from dynamic_cssc.followup_performance_lineage import (
    FollowupLineageError,
    produce_followup_registration_archive,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--s1", required=True)
    parser.add_argument("--s2", required=True)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        if not arguments.repository_root.is_absolute() or not arguments.output.is_absolute():
            raise FollowupLineageError("follow-up registration paths must be absolute")
        if arguments.output.exists() or arguments.output.is_symlink():
            raise FollowupLineageError("follow-up registration output must be absent")
        archive = produce_followup_registration_archive(
            arguments.repository_root,
            s1=arguments.s1,
            s2=arguments.s2,
        )
        with arguments.output.open("xb") as output:
            output.write(archive.archive_bytes)
            output.flush()
            os.fsync(output.fileno())
        print(
            json.dumps(
                {
                    "archive_sha256": archive.archive_sha256,
                    "artifact_name": archive.artifact_name,
                    "authority": False,
                    "compatibility_receipt_sha256": (
                        archive.compatibility_receipt_sha256
                    ),
                    "envelope_sha256": archive.envelope_sha256,
                    "formal_execution_authorized": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        print(f"follow-up registration failed closed: {error}", file=os.sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
