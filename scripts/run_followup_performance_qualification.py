#!/usr/bin/env python3
"""Run q1/q2 for the one-shot follow-up qualification."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path

from dynamic_cssc.followup_performance_artifacts import (
    inspect_followup_qualification_artifact,
    produce_followup_qualification_artifact,
)
from dynamic_cssc.followup_performance_contract import (
    materialize_followup_scientific_plan,
)
from dynamic_cssc.route_a_qualification_runtime import (
    RouteAQualificationRuntimeError,
    inspect_route_a_qualification_stage_artifact,
    route_a_stage_observer,
    run_owned_route_a_qualification_stage,
)
from dynamic_cssc.route_a_synthetic_suite import (
    RouteASyntheticSuiteLineage,
    produce_route_a_synthetic_suite_handoff,
    replay_and_guard_route_a_synthetic_suite,
)
from dynamic_cssc.route_a_workloads import generate_route_a_qualification_trace

_WORKER_SCRIPT = "scripts/run_followup_performance_qualification.py"


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
        raise RouteAQualificationRuntimeError(
            "follow-up qualification requires one clean detached exact-S1 checkout"
        )


def _worker(arguments: argparse.Namespace) -> int:
    scientific = materialize_followup_scientific_plan(arguments.repository_root)
    lineage = _lineage(arguments)
    profile = scientific.scientific_profile
    trace = generate_route_a_qualification_trace(
        scale="M",
        qualification_seed=profile.qualification_seed,
        scientific_profile=profile,
    )
    observer = route_a_stage_observer(
        arguments.stage_write_fd,
        arguments.acknowledgement_read_fd,
    )
    if arguments.stage == "q1":
        if arguments.producer_artifact_directory is not None:
            raise RouteAQualificationRuntimeError("follow-up q1 worker received a q1 artifact")
        produce_route_a_synthetic_suite_handoff(
            trace,
            lineage=lineage,
            machine_plan_bytes=scientific.machine_plan_bytes,
            scratch_root=arguments.scratch_root,
            output_path=arguments.output,
            stage_observer=observer,
            scientific_profile=profile,
        )
    else:
        if arguments.producer_artifact_directory is None:
            raise RouteAQualificationRuntimeError("follow-up q2 worker lacks its exact q1 tree")
        producer = inspect_route_a_qualification_stage_artifact(
            arguments.producer_artifact_directory,
            expected_stage="q1",
            expected_lineage=lineage,
        )
        replay_and_guard_route_a_synthetic_suite(
            trace,
            lineage=lineage,
            machine_plan_bytes=scientific.machine_plan_bytes,
            producer_archive_path=producer.payload_path,
            scratch_root=arguments.scratch_root,
            output_path=arguments.output,
            stage_observer=observer,
            scientific_profile=profile,
        )
    return 0


def _parent(arguments: argparse.Namespace) -> int:
    _verify_exact_checkout(arguments.repository_root, arguments.experiment_source_sha)
    scientific = materialize_followup_scientific_plan(arguments.repository_root)
    lineage = _lineage(arguments)
    producer_inner: Path | None = None
    if arguments.stage == "q2":
        if arguments.producer_artifact_directory is None:
            raise RouteAQualificationRuntimeError("follow-up q2 lacks its q1 wrapper")
        producer_inner = inspect_followup_qualification_artifact(
            arguments.producer_artifact_directory,
            stage="q1",
            lineage=lineage,
            scientific_profile=scientific.scientific_profile,
            machine_plan_bytes=scientific.machine_plan_bytes,
            repository_root=arguments.repository_root,
        ).inner_directory
    elif arguments.producer_artifact_directory is not None:
        raise RouteAQualificationRuntimeError("follow-up q1 cannot consume a producer wrapper")

    inner_output = arguments.output_directory.parent / (
        f".{arguments.output_directory.name}-inherited-{os.getpid()}"
    )
    if inner_output.exists() or inner_output.is_symlink():
        raise RouteAQualificationRuntimeError("follow-up inherited output path already exists")
    try:
        run_owned_route_a_qualification_stage(
            stage=arguments.stage,
            repository_root=arguments.repository_root,
            lineage=lineage,
            scratch_parent=arguments.scratch_parent,
            output_directory=inner_output,
            producer_artifact_directory=producer_inner,
            scientific_profile=scientific.scientific_profile,
            machine_plan_bytes=scientific.machine_plan_bytes,
            worker_script_relative_path=_WORKER_SCRIPT,
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
                "inner_sha256": inspection.envelope.document["inner_sha256"],
                "unit_identity_sha256": inspection.unit_identity_sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("run", "_worker"):
        selected = subparsers.add_parser(command)
        selected.add_argument("--stage", required=True, choices=("q1", "q2"))
        selected.add_argument("--repository-root", required=True, type=Path)
        selected.add_argument("--experiment-source-sha", required=True)
        selected.add_argument("--workflow-head-sha", required=True)
        selected.add_argument("--compatibility-receipt-sha256", required=True)
        selected.add_argument("--provider-run-id", required=True, type=int)
        selected.add_argument("--provider-run-attempt", required=True, type=int, choices=(1,))
        selected.add_argument("--producer-artifact-directory", type=Path)
    parent = subparsers.choices["run"]
    parent.add_argument("--scratch-parent", required=True, type=Path)
    parent.add_argument("--output-directory", required=True, type=Path)
    worker = subparsers.choices["_worker"]
    worker.add_argument("--scratch-root", required=True, type=Path)
    worker.add_argument("--output", required=True, type=Path)
    worker.add_argument("--stage-write-fd", required=True, type=int)
    worker.add_argument("--acknowledgement-read-fd", required=True, type=int)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        if arguments.command == "_worker":
            return _worker(arguments)
        return _parent(arguments)
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        print(f"follow-up qualification failed closed: {error}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
