#!/usr/bin/env python3
"""Create a review-only Day 2 post-run anchor proposal from downloaded files."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from dynamic_cssc.day2_calibration_postrun import (  # noqa: E402
    propose_repository_day2_calibration_post_run_anchor,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Propose, but do not install, a reviewed Day 2 repository anchor."
    )
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--github-artifact-metadata", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    proposal = propose_repository_day2_calibration_post_run_anchor(
        arguments.archive,
        arguments.github_artifact_metadata,
        arguments.output_directory,
    )
    print(
        json.dumps(
            {
                "anchor_document_sha256": proposal.anchor_document_sha256,
                "formal_authority_granted": proposal.formal_authority_granted,
                "outer_archive_sha256": proposal.outer_archive_sha256,
                "output_directory": str(proposal.output_dir),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
