#!/usr/bin/env python3
"""Run the closed simulator stages of the non-admissible Route A qualification."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from dynamic_cssc.route_a_qualification_runtime import (
    RouteAQualificationRuntimeError,
    inspect_route_a_qualification_stage_artifact,
    route_a_stage_observer,
    run_owned_route_a_qualification_stage,
)
from dynamic_cssc.route_a_synthetic_suite import (
    RouteASyntheticSuiteError,
    RouteASyntheticSuiteLineage,
    produce_route_a_synthetic_suite_handoff,
    replay_and_guard_route_a_synthetic_suite,
)
from dynamic_cssc.route_a_workloads import generate_route_a_qualification_trace


def _lineage(arguments: argparse.Namespace) -> RouteASyntheticSuiteLineage:
    return RouteASyntheticSuiteLineage(
        experiment_source_sha=arguments.experiment_source_sha,
        workflow_head_sha=arguments.workflow_head_sha,
        compatibility_receipt_sha256=arguments.compatibility_receipt_sha256,
        provider_run_id=arguments.provider_run_id,
        provider_run_attempt=arguments.provider_run_attempt,
    )


def _verify_exact_checkout(repository_root: Path, expected_s1: str) -> None:
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "HOME": os.environ.get("HOME", str(repository_root)),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
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
        raise RouteAQualificationRuntimeError(
            "qualification requires one clean detached exact-S1 checkout"
        )


def _worker(arguments: argparse.Namespace) -> int:
    lineage = _lineage(arguments)
    trace = generate_route_a_qualification_trace(scale="M", qualification_seed=20260821)
    plan_bytes = (arguments.repository_root / "config/route-a-publication-plan.json").read_bytes()
    observer = route_a_stage_observer(arguments.stage_write_fd, arguments.acknowledgement_read_fd)
    if arguments.stage == "q1":
        if arguments.producer_artifact_directory is not None:
            raise RouteAQualificationRuntimeError("q1 worker received a q1 artifact")
        produce_route_a_synthetic_suite_handoff(
            trace,
            lineage=lineage,
            machine_plan_bytes=plan_bytes,
            scratch_root=arguments.scratch_root,
            output_path=arguments.output,
            stage_observer=observer,
        )
    else:
        if arguments.producer_artifact_directory is None:
            raise RouteAQualificationRuntimeError("q2 worker lacks its exact q1 artifact")
        producer = inspect_route_a_qualification_stage_artifact(
            arguments.producer_artifact_directory,
            expected_stage="q1",
            expected_lineage=lineage,
        )
        replay_and_guard_route_a_synthetic_suite(
            trace,
            lineage=lineage,
            machine_plan_bytes=plan_bytes,
            producer_archive_path=producer.payload_path,
            scratch_root=arguments.scratch_root,
            output_path=arguments.output,
            stage_observer=observer,
        )
    return 0


def _parent(arguments: argparse.Namespace) -> int:
    _verify_exact_checkout(arguments.repository_root, arguments.experiment_source_sha)
    inspection = run_owned_route_a_qualification_stage(
        stage=arguments.stage,
        repository_root=arguments.repository_root,
        lineage=_lineage(arguments),
        scratch_parent=arguments.scratch_parent,
        output_directory=arguments.output_directory,
        producer_artifact_directory=arguments.producer_artifact_directory,
    )
    print(
        inspection.payload_sha256,
        inspection.payload_byte_count,
        inspection.stage,
        sep="\t",
    )
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    parent = subparsers.add_parser("run")
    parent.add_argument("--stage", required=True, choices=("q1", "q2"))
    parent.add_argument("--repository-root", required=True, type=Path)
    parent.add_argument("--experiment-source-sha", required=True)
    parent.add_argument("--workflow-head-sha", required=True)
    parent.add_argument("--compatibility-receipt-sha256", required=True)
    parent.add_argument("--provider-run-id", required=True, type=int)
    parent.add_argument("--provider-run-attempt", required=True, type=int, choices=(1,))
    parent.add_argument("--scratch-parent", required=True, type=Path)
    parent.add_argument("--output-directory", required=True, type=Path)
    parent.add_argument("--producer-artifact-directory", type=Path)

    worker = subparsers.add_parser("_worker")
    worker.add_argument("--stage", required=True, choices=("q1", "q2"))
    worker.add_argument("--repository-root", required=True, type=Path)
    worker.add_argument("--experiment-source-sha", required=True)
    worker.add_argument("--workflow-head-sha", required=True)
    worker.add_argument("--compatibility-receipt-sha256", required=True)
    worker.add_argument("--provider-run-id", required=True, type=int)
    worker.add_argument("--provider-run-attempt", required=True, type=int, choices=(1,))
    worker.add_argument("--scratch-root", required=True, type=Path)
    worker.add_argument("--output", required=True, type=Path)
    worker.add_argument("--stage-write-fd", required=True, type=int)
    worker.add_argument("--acknowledgement-read-fd", required=True, type=int)
    worker.add_argument("--producer-artifact-directory", type=Path)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        if arguments.command == "_worker":
            return _worker(arguments)
        return _parent(arguments)
    except (
        OSError,
        RouteAQualificationRuntimeError,
        RouteASyntheticSuiteError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
    ) as error:
        print(f"Route A qualification failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
