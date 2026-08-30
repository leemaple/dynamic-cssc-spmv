#!/usr/bin/env python3
"""Package and independently reinspect one follow-up control receipt."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from dynamic_cssc.followup_performance_control_artifacts import (
    FollowupControlArtifactError,
    produce_followup_control_artifact,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--kind",
        required=True,
        choices=("ci", "pre-s1", "independent-review", "source-anchor"),
    )
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        if not arguments.receipt.is_absolute() or not arguments.output_directory.is_absolute():
            raise FollowupControlArtifactError("control artifact paths must be absolute")
        inspection = produce_followup_control_artifact(
            arguments.receipt.read_bytes(),
            arguments.output_directory,
            kind=arguments.kind,
        )
        print(
            json.dumps(
                {
                    "artifact_name": inspection.artifact_name,
                    "authority": False,
                    "envelope_sha256": inspection.envelope.sha256,
                    "formal_execution_authorized": False,
                    "receipt_sha256": inspection.envelope.document["inner_sha256"],
                    "unit_identity_sha256": inspection.unit_identity_sha256,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        print(f"follow-up control artifact failed closed: {error}", file=os.sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
