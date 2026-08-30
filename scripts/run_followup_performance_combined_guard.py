#!/usr/bin/env python3
"""Run the follow-up q5 combined guard over exact outer q2/q4 artifacts."""

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
from dynamic_cssc.route_a_qualification_guard import (
    RouteACombinedGuardError,
    produce_route_a_combined_guard,
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
        raise RouteACombinedGuardError(
            "follow-up q5 requires a clean detached exact-S1 checkout"
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--experiment-source-sha", required=True)
    parser.add_argument("--workflow-head-sha", required=True)
    parser.add_argument("--compatibility-receipt-sha256", required=True)
    parser.add_argument("--provider-run-id", required=True, type=int)
    parser.add_argument("--provider-run-attempt", required=True, type=int, choices=(1,))
    parser.add_argument("--provider-artifacts-json", required=True, type=Path)
    parser.add_argument("--q2-wrapper", required=True, type=Path)
    parser.add_argument("--q4-wrapper", required=True, type=Path)
    parser.add_argument("--scratch-parent", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    return parser


def _main(arguments: argparse.Namespace) -> int:
    paths = (
        arguments.repository_root,
        arguments.provider_artifacts_json,
        arguments.q2_wrapper,
        arguments.q4_wrapper,
        arguments.scratch_parent,
        arguments.output_directory,
    )
    if any(not path.is_absolute() for path in paths):
        raise RouteACombinedGuardError("all follow-up q5 paths must be absolute")
    _verify_exact_checkout(arguments.repository_root, arguments.experiment_source_sha)
    scientific = materialize_followup_scientific_plan(arguments.repository_root)
    lineage = RouteASyntheticSuiteLineage(
        experiment_source_sha=arguments.experiment_source_sha,
        workflow_head_sha=arguments.workflow_head_sha,
        compatibility_receipt_sha256=arguments.compatibility_receipt_sha256,
        provider_run_id=arguments.provider_run_id,
        provider_run_attempt=arguments.provider_run_attempt,
    )
    q2_name = expected_followup_qualification_artifact_name(
        stage="q2",
        lineage=lineage,
        scientific_profile=scientific.scientific_profile,
    )
    q4_name = expected_followup_qualification_artifact_name(
        stage="q4",
        lineage=lineage,
        scientific_profile=scientific.scientific_profile,
    )
    inner_output = arguments.output_directory.parent / (
        f".{arguments.output_directory.name}-inherited-{os.getpid()}"
    )
    if inner_output.exists() or inner_output.is_symlink():
        raise RouteACombinedGuardError("follow-up q5 inherited output already exists")
    try:
        produce_route_a_combined_guard(
            repository_root=arguments.repository_root,
            lineage=lineage,
            provider_artifacts_json_path=arguments.provider_artifacts_json,
            q2_wrapper_path=arguments.q2_wrapper,
            q4_wrapper_path=arguments.q4_wrapper,
            scratch_parent=arguments.scratch_parent,
            output_directory=inner_output,
            scientific_profile=scientific.scientific_profile,
            machine_plan_bytes=scientific.machine_plan_bytes,
            q2_provider_name=q2_name,
            q4_provider_name=q4_name,
            followup_outer_wrappers=True,
        )
        inspection = produce_followup_qualification_artifact(
            inner_output,
            arguments.output_directory,
            stage="q5",
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
                "inner_stage_manifest_sha256": inspection.inherited.manifest_sha256,
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
        print(f"follow-up combined guard failed closed: {error}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
