#!/usr/bin/env python3
"""Render one canonical success-only follow-up control receipt."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from dynamic_cssc.followup_performance_control_artifacts import (
    FollowupControlArtifactError,
    build_followup_control_receipt,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--kind",
        required=True,
        choices=("ci", "pre-s1", "independent-review", "source-anchor"),
    )
    parser.add_argument("--experiment-source-s1-sha", required=True)
    parser.add_argument("--evidence-freeze-s2-sha", required=True)
    parser.add_argument("--compatibility-receipt-sha256", required=True)
    parser.add_argument("--provider-run-id", required=True, type=int)
    parser.add_argument("--provider-run-attempt", required=True, type=int, choices=(1,))
    parser.add_argument("--detail", action="append", default=[])
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        if not arguments.output.is_absolute() or arguments.output.exists():
            raise FollowupControlArtifactError("control receipt output is unsafe")
        details: dict[str, str] = {}
        for value in arguments.detail:
            if "=" not in value:
                raise FollowupControlArtifactError("control detail lacks one equals sign")
            key, detail = value.split("=", 1)
            if not key or not detail or key in details:
                raise FollowupControlArtifactError("control detail is empty or duplicated")
            details[key] = detail
        details = dict(sorted(details.items()))
        receipt = build_followup_control_receipt(
            kind=arguments.kind,
            experiment_source_s1_sha=arguments.experiment_source_s1_sha,
            evidence_freeze_s2_sha=arguments.evidence_freeze_s2_sha,
            compatibility_receipt_sha256=arguments.compatibility_receipt_sha256,
            provider_run_id=arguments.provider_run_id,
            provider_run_attempt=arguments.provider_run_attempt,
            details=details,
        )
        with arguments.output.open("xb") as output:
            output.write(receipt)
            output.flush()
            os.fsync(output.fileno())
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        print(f"follow-up control receipt failed closed: {error}", file=os.sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
