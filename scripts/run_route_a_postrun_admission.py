#!/usr/bin/env python3
"""Run q6's read-only provider-state admission record producer."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from dynamic_cssc.route_a_postrun_admission import (
    RouteAPostrunAdmissionError,
    produce_route_a_postrun_admission,
)


def _verify_exact_checkout(repository_root: Path, expected_s1: str) -> None:
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    head = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=repository_root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    status = subprocess.run(
        ("git", "status", "--porcelain=v1", "--untracked-files=no"),
        cwd=repository_root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if head != expected_s1 or status:
        raise RouteAPostrunAdmissionError(
            "q6 requires one clean detached exact-S1 behavior checkout"
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--experiment-source-sha", required=True)
    parser.add_argument("--expected-s2-git-sha", required=True)
    parser.add_argument("--expected-head-branch", required=True, choices=("main",))
    parser.add_argument("--expected-run-id", required=True, type=int)
    parser.add_argument("--expected-run-attempt", required=True, type=int, choices=(1,))
    parser.add_argument("--run-json", required=True, type=Path)
    parser.add_argument("--jobs-json", required=True, type=Path)
    parser.add_argument("--artifacts-json", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        paths = (
            arguments.repository_root,
            arguments.run_json,
            arguments.jobs_json,
            arguments.artifacts_json,
            arguments.output_directory,
        )
        if any(not path.is_absolute() for path in paths):
            raise RouteAPostrunAdmissionError("all q6 paths must be absolute")
        _verify_exact_checkout(arguments.repository_root, arguments.experiment_source_sha)
        inspection = produce_route_a_postrun_admission(
            run_json_path=arguments.run_json,
            jobs_json_path=arguments.jobs_json,
            artifacts_json_path=arguments.artifacts_json,
            expected_run_id=arguments.expected_run_id,
            expected_s2_git_sha=arguments.expected_s2_git_sha,
            expected_head_branch=arguments.expected_head_branch,
            expected_run_attempt=arguments.expected_run_attempt,
            output_directory=arguments.output_directory,
        )
        print(
            json.dumps(
                {
                    "authority_granted": False,
                    "formal_execution_authorized": False,
                    "publication_evidence": False,
                    "record_sha256": inspection.record_sha256,
                    "stage": "q6",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except (
        OSError,
        RouteAPostrunAdmissionError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
    ) as error:
        print(f"Route A postrun admission failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
