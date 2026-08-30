#!/usr/bin/env python3
"""Verify and address the exact follow-up S1/S2 compatibility receipt."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from dynamic_cssc.followup_performance_lineage import (
    FollowupLineageError,
    verify_followup_s1_s2_compatibility,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--s1", required=True)
    parser.add_argument("--s2", required=True)
    parser.add_argument("--expected-receipt-sha256", required=True)
    arguments = parser.parse_args()
    try:
        if not arguments.repository_root.is_absolute():
            raise FollowupLineageError("repository_root must be absolute")
        receipt = verify_followup_s1_s2_compatibility(
            arguments.repository_root,
            s1=arguments.s1,
            s2=arguments.s2,
        )
        if receipt.sha256 != arguments.expected_receipt_sha256:
            raise FollowupLineageError("follow-up compatibility receipt address changed")
        print(
            json.dumps(
                {
                    "authority": False,
                    "compatibility_receipt_sha256": receipt.sha256,
                    "compatibility_verified": True,
                    "formal_execution_authorized": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        print(f"follow-up lineage verification failed closed: {error}", file=os.sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
