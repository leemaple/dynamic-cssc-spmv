#!/usr/bin/env python3
"""Run q3/q4 for the one-shot follow-up native qualification."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path

from dynamic_cssc.followup_performance_artifacts import (
    FollowupArtifactError,
    inspect_followup_qualification_artifact,
    produce_followup_qualification_artifact,
)
from dynamic_cssc.followup_performance_contract import (
    FollowupContractError,
    materialize_followup_scientific_plan,
)
from dynamic_cssc.route_a_native_suite import (
    RouteANativeQualificationError,
    produce_route_a_native_qualification_handoff,
    replay_and_guard_route_a_native_qualification,
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
        raise RouteANativeQualificationError(
            "follow-up native qualification requires a clean detached exact-S1 checkout"
        )


def _lineage(arguments: argparse.Namespace) -> RouteASyntheticSuiteLineage:
    return RouteASyntheticSuiteLineage(
        experiment_source_sha=arguments.experiment_source_sha,
        workflow_head_sha=arguments.workflow_head_sha,
        compatibility_receipt_sha256=arguments.compatibility_receipt_sha256,
        provider_run_id=arguments.provider_run_id,
        provider_run_attempt=arguments.provider_run_attempt,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", required=True, choices=("q3", "q4"))
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--experiment-source-sha", required=True)
    parser.add_argument("--workflow-head-sha", required=True)
    parser.add_argument("--compatibility-receipt-sha256", required=True)
    parser.add_argument("--provider-run-id", required=True, type=int)
    parser.add_argument("--provider-run-attempt", required=True, type=int, choices=(1,))
    parser.add_argument("--scratch-parent", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument("--q3-artifact-directory", type=Path)
    parser.add_argument("--timeout-seconds-per-process", type=int, default=900)
    parser.add_argument("--resident-memory-limit-bytes", type=int, default=7 * 1024**3)
    parser.add_argument("--scratch-limit-bytes", type=int, default=8 * 1024**3)
    return parser


def _main(arguments: argparse.Namespace) -> int:
    for field in ("repository_root", "scratch_parent", "output_directory"):
        if not getattr(arguments, field).is_absolute():
            raise RouteANativeQualificationError(f"{field} must be an absolute path")
    if (
        arguments.q3_artifact_directory is not None
        and not arguments.q3_artifact_directory.is_absolute()
    ):
        raise RouteANativeQualificationError(
            "q3_artifact_directory must be an absolute path"
        )
    _verify_exact_checkout(arguments.repository_root, arguments.experiment_source_sha)
    scientific = materialize_followup_scientific_plan(arguments.repository_root)
    lineage = _lineage(arguments)
    q3_inner: Path | None = None
    expected_q3_manifest_sha256: str | None = None
    if arguments.stage == "q3":
        if arguments.q3_artifact_directory is not None:
            raise RouteANativeQualificationError("follow-up q3 cannot consume a q3 wrapper")
    else:
        if arguments.q3_artifact_directory is None:
            raise RouteANativeQualificationError("follow-up q4 requires its exact q3 wrapper")
        q3 = inspect_followup_qualification_artifact(
            arguments.q3_artifact_directory,
            stage="q3",
            lineage=lineage,
            scientific_profile=scientific.scientific_profile,
            machine_plan_bytes=scientific.machine_plan_bytes,
            repository_root=arguments.repository_root,
        )
        q3_inner = q3.inner_directory
        expected_q3_manifest_sha256 = q3.inherited.manifest_sha256

    inner_output = arguments.output_directory.parent / (
        f".{arguments.output_directory.name}-inherited-{os.getpid()}"
    )
    if inner_output.exists() or inner_output.is_symlink():
        raise RouteANativeQualificationError("follow-up inherited output path already exists")
    common = {
        "repository_root": arguments.repository_root,
        "lineage": lineage,
        "scratch_parent": arguments.scratch_parent,
        "output_directory": inner_output,
        "timeout_seconds_per_process": arguments.timeout_seconds_per_process,
        "resident_memory_limit_bytes": arguments.resident_memory_limit_bytes,
        "scratch_limit_bytes": arguments.scratch_limit_bytes,
        "scientific_profile": scientific.scientific_profile,
        "machine_plan_bytes": scientific.machine_plan_bytes,
    }
    try:
        if arguments.stage == "q3":
            produce_route_a_native_qualification_handoff(**common)
        else:
            assert q3_inner is not None
            assert expected_q3_manifest_sha256 is not None
            replay_and_guard_route_a_native_qualification(
                **common,
                q3_artifact_directory=q3_inner,
                expected_q3_manifest_sha256=expected_q3_manifest_sha256,
            )
        inspection = produce_followup_qualification_artifact(
            inner_output,
            arguments.output_directory,
            stage=arguments.stage,
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
    except (
        FollowupArtifactError,
        FollowupContractError,
        OSError,
        RouteANativeQualificationError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
    ) as error:
        print(f"follow-up native qualification failed closed: {error}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
