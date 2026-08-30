#!/usr/bin/env python3
"""Produce and outer-wrap the follow-up q6 postrun admission record."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path

from dynamic_cssc.followup_performance_artifacts import (
    expected_followup_qualification_artifact_name,
    produce_followup_qualification_artifact,
)
from dynamic_cssc.followup_performance_contract import (
    materialize_followup_scientific_plan,
)
from dynamic_cssc.route_a_postrun_admission import (
    RouteAPostrunAdmissionError,
    produce_route_a_postrun_admission,
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
        (
            "git",
            "--no-replace-objects",
            "status",
            "--porcelain=v1",
            "--untracked-files=no",
        ),
        cwd=repository_root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if head != expected_s1 or status:
        raise RouteAPostrunAdmissionError(
            "follow-up q6 requires a clean detached exact-S1 checkout"
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--experiment-source-sha", required=True)
    parser.add_argument("--workflow-head-sha", required=True)
    parser.add_argument("--compatibility-receipt-sha256", required=True)
    parser.add_argument("--expected-head-branch", required=True, choices=("main",))
    parser.add_argument("--provider-run-id", required=True, type=int)
    parser.add_argument("--provider-run-attempt", required=True, type=int, choices=(1,))
    parser.add_argument("--run-json", required=True, type=Path)
    parser.add_argument("--jobs-json", required=True, type=Path)
    parser.add_argument("--artifacts-json", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    return parser


def _main(arguments: argparse.Namespace) -> int:
    paths = (
        arguments.repository_root,
        arguments.run_json,
        arguments.jobs_json,
        arguments.artifacts_json,
        arguments.output_directory,
    )
    if any(not path.is_absolute() for path in paths):
        raise RouteAPostrunAdmissionError("all follow-up q6 paths must be absolute")
    _verify_exact_checkout(arguments.repository_root, arguments.experiment_source_sha)
    scientific = materialize_followup_scientific_plan(arguments.repository_root)
    lineage = RouteASyntheticSuiteLineage(
        experiment_source_sha=arguments.experiment_source_sha,
        workflow_head_sha=arguments.workflow_head_sha,
        compatibility_receipt_sha256=arguments.compatibility_receipt_sha256,
        provider_run_id=arguments.provider_run_id,
        provider_run_attempt=arguments.provider_run_attempt,
    )
    expected_prefix_artifacts = tuple(
        expected_followup_qualification_artifact_name(
            stage=stage,
            lineage=lineage,
            scientific_profile=scientific.scientific_profile,
        )
        for stage in ("q1", "q2", "q3", "q4", "q5")
    )
    inner_output = arguments.output_directory.parent / (
        f".{arguments.output_directory.name}-inherited-{os.getpid()}"
    )
    if inner_output.exists() or inner_output.is_symlink():
        raise RouteAPostrunAdmissionError("follow-up q6 inherited output already exists")
    try:
        produce_route_a_postrun_admission(
            run_json_path=arguments.run_json,
            jobs_json_path=arguments.jobs_json,
            artifacts_json_path=arguments.artifacts_json,
            expected_run_id=arguments.provider_run_id,
            expected_s2_git_sha=arguments.workflow_head_sha,
            expected_head_branch=arguments.expected_head_branch,
            expected_run_attempt=arguments.provider_run_attempt,
            output_directory=inner_output,
            expected_prefix_artifact_names=expected_prefix_artifacts,
        )
        inspection = produce_followup_qualification_artifact(
            inner_output,
            arguments.output_directory,
            stage="q6",
            lineage=lineage,
            scientific_profile=scientific.scientific_profile,
            machine_plan_bytes=scientific.machine_plan_bytes,
            repository_root=arguments.repository_root,
        )
    finally:
        if inner_output.exists() and not inner_output.is_symlink():
            shutil.rmtree(inner_output, ignore_errors=True)
    print(
        json.dumps(
            {
                "artifact_name": inspection.artifact_name,
                "inner_record_sha256": inspection.inherited.record_sha256,
                "inner_tree_sha256": inspection.envelope.document["inner_sha256"],
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
    except (OSError, RuntimeError, subprocess.SubprocessError, TypeError, ValueError) as error:
        print(f"follow-up postrun admission failed closed: {error}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
