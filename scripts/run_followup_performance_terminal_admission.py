#!/usr/bin/env python3
"""Reinspect, time-close, and admit the complete follow-up formal set."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

from dynamic_cssc.followup_performance_contract import (
    FollowupContractError,
    materialize_followup_scientific_plan,
)
from dynamic_cssc.followup_performance_formal_timing import (
    inspect_followup_formal_timing_prefix,
)
from dynamic_cssc.followup_performance_lineage import (
    verify_followup_s1_s2_compatibility,
)
from dynamic_cssc.followup_performance_terminal import (
    FollowupTerminalAdmissionError,
    inspect_followup_formal_artifact_set,
    produce_followup_terminal_admission,
)
from dynamic_cssc.route_a_synthetic_suite import RouteASyntheticSuiteLineage


def _verify_exact_checkout(repository_root: Path, expected_s1: str) -> None:
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }
    head = subprocess.run(
        ("git", "--no-replace-objects", "rev-parse", "HEAD"),
        cwd=repository_root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    status = subprocess.run(
        ("git", "--no-replace-objects", "status", "--porcelain=v1", "--untracked-files=no"),
        cwd=repository_root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if head != expected_s1 or status:
        raise FollowupTerminalAdmissionError(
            "terminal admission requires a clean detached exact-S1 checkout"
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--experiment-source-sha", required=True)
    parser.add_argument("--workflow-head-sha", required=True)
    parser.add_argument("--compatibility-receipt-sha256", required=True)
    parser.add_argument("--provider-run-id", required=True, type=int)
    parser.add_argument("--provider-run-attempt", required=True, type=int, choices=(1,))
    parser.add_argument("--expected-head-branch", default="main")
    parser.add_argument("--formal-artifact-root", required=True, type=Path)
    parser.add_argument("--run-json", required=True, type=Path)
    parser.add_argument("--jobs-json", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    return parser


def _main(arguments: argparse.Namespace) -> int:
    paths = (
        arguments.repository_root,
        arguments.formal_artifact_root,
        arguments.run_json,
        arguments.jobs_json,
        arguments.output_directory,
    )
    if any(not path.is_absolute() for path in paths):
        raise FollowupTerminalAdmissionError(
            "terminal admission paths must be absolute"
        )
    _verify_exact_checkout(arguments.repository_root, arguments.experiment_source_sha)
    compatibility = verify_followup_s1_s2_compatibility(
        arguments.repository_root,
        s1=arguments.experiment_source_sha,
        s2=arguments.workflow_head_sha,
    )
    if compatibility.sha256 != arguments.compatibility_receipt_sha256:
        raise FollowupTerminalAdmissionError(
            "terminal admission compatibility receipt changed"
        )
    scientific = materialize_followup_scientific_plan(arguments.repository_root)
    lineage = RouteASyntheticSuiteLineage(
        experiment_source_sha=arguments.experiment_source_sha,
        workflow_head_sha=arguments.workflow_head_sha,
        compatibility_receipt_sha256=arguments.compatibility_receipt_sha256,
        provider_run_id=arguments.provider_run_id,
        provider_run_attempt=arguments.provider_run_attempt,
    )
    timing = inspect_followup_formal_timing_prefix(
        arguments.run_json.read_bytes(),
        arguments.jobs_json.read_bytes(),
        lineage=lineage,
        scientific_profile=scientific.scientific_profile,
        expected_head_branch=arguments.expected_head_branch,
    )
    artifact_set = inspect_followup_formal_artifact_set(
        arguments.formal_artifact_root,
        repository_root=arguments.repository_root,
        lineage=lineage,
        scientific_profile=scientific.scientific_profile,
        machine_plan_bytes=scientific.machine_plan_bytes,
    )
    inspection = produce_followup_terminal_admission(
        artifact_set,
        arguments.output_directory,
        lineage=lineage,
        timing_ledger=timing,
    )
    print(
        json.dumps(
            {
                "artifact_name": inspection.artifact_name,
                "formal_artifact_set_sha256": inspection.formal_artifact_set_sha256,
                "formal_timing_ledger_sha256": inspection.formal_timing_ledger_sha256,
                "unit_identity_sha256": inspection.unit_identity_sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def main() -> int:
    try:
        return _main(_parser().parse_args())
    except (
        FollowupContractError,
        FollowupTerminalAdmissionError,
        OSError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
    ) as error:
        print(f"follow-up terminal admission failed closed: {error}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
