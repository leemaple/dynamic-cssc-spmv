#!/usr/bin/env python3
"""Run one formal native OpenFHE producer or independent replay and guard."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path

from dynamic_cssc.followup_performance_contract import (
    FollowupContractError,
    materialize_followup_scientific_plan,
)
from dynamic_cssc.followup_performance_formal_native_artifacts import (
    FollowupFormalNativeArtifactError,
    inspect_followup_formal_native_artifact,
    produce_followup_formal_native_artifact,
)
from dynamic_cssc.followup_performance_lineage import (
    verify_followup_s1_s2_compatibility,
)
from dynamic_cssc.route_a_native_suite import (
    RouteANativeQualificationError,
    compile_route_a_native_formal_case,
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
        ("git", "--no-replace-objects", "status", "--porcelain=v1", "--untracked-files=no"),
        cwd=repository_root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if head != expected_s1 or status:
        raise FollowupFormalNativeArtifactError(
            "formal native execution requires a clean detached exact-S1 checkout"
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", required=True, choices=("private-handoff", "guarded-final"))
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--experiment-source-sha", required=True)
    parser.add_argument("--workflow-head-sha", required=True)
    parser.add_argument("--compatibility-receipt-sha256", required=True)
    parser.add_argument("--provider-run-id", required=True, type=int)
    parser.add_argument("--provider-run-attempt", required=True, type=int, choices=(1,))
    parser.add_argument("--scale", required=True, choices=("S", "M"))
    parser.add_argument("--formal-seed", required=True, type=int)
    parser.add_argument("--strategy-candidate-id", required=True)
    parser.add_argument("--unit-attempt-ordinal", type=int, default=1, choices=(1,))
    parser.add_argument("--scratch-parent", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument("--producer-artifact-directory", type=Path)
    parser.add_argument("--timeout-seconds-per-process", type=int, default=900)
    parser.add_argument("--resident-memory-limit-bytes", type=int, default=7 * 1024**3)
    parser.add_argument("--scratch-limit-bytes", type=int, default=8 * 1024**3)
    return parser


def _main(arguments: argparse.Namespace) -> int:
    paths = (
        arguments.repository_root,
        arguments.scratch_parent,
        arguments.output_directory,
    )
    if any(not path.is_absolute() for path in paths) or (
        arguments.producer_artifact_directory is not None
        and not arguments.producer_artifact_directory.is_absolute()
    ):
        raise FollowupFormalNativeArtifactError("formal native paths must be absolute")
    _verify_exact_checkout(arguments.repository_root, arguments.experiment_source_sha)
    compatibility = verify_followup_s1_s2_compatibility(
        arguments.repository_root,
        s1=arguments.experiment_source_sha,
        s2=arguments.workflow_head_sha,
    )
    if compatibility.sha256 != arguments.compatibility_receipt_sha256:
        raise FollowupFormalNativeArtifactError("formal native compatibility receipt changed")
    scientific = materialize_followup_scientific_plan(arguments.repository_root)
    profile = scientific.scientific_profile
    lineage = RouteASyntheticSuiteLineage(
        experiment_source_sha=arguments.experiment_source_sha,
        workflow_head_sha=arguments.workflow_head_sha,
        compatibility_receipt_sha256=arguments.compatibility_receipt_sha256,
        provider_run_id=arguments.provider_run_id,
        provider_run_attempt=arguments.provider_run_attempt,
    )
    case = compile_route_a_native_formal_case(
        arguments.repository_root,
        lineage,
        scale=arguments.scale,
        formal_seed=arguments.formal_seed,
        strategy_candidate_id=arguments.strategy_candidate_id,
        unit_attempt_ordinal=0,
        scientific_profile=profile,
        machine_plan_bytes=scientific.machine_plan_bytes,
    )
    producer_inner: Path | None = None
    expected_q3_manifest: str | None = None
    if arguments.phase == "private-handoff":
        if arguments.producer_artifact_directory is not None:
            raise FollowupFormalNativeArtifactError(
                "formal native producer received a producer artifact"
            )
    else:
        if arguments.producer_artifact_directory is None:
            raise FollowupFormalNativeArtifactError(
                "formal native replay lacks its producer artifact"
            )
        producer = inspect_followup_formal_native_artifact(
            arguments.producer_artifact_directory,
            phase="private-handoff",
            repository_root=arguments.repository_root,
            lineage=lineage,
            scale=arguments.scale,
            formal_seed=arguments.formal_seed,
            strategy_candidate_id=arguments.strategy_candidate_id,
            scientific_profile=profile,
            machine_plan_bytes=scientific.machine_plan_bytes,
            unit_attempt_ordinal=arguments.unit_attempt_ordinal,
        )
        producer_inner = producer.inner_directory
        expected_q3_manifest = producer.inherited.manifest_sha256

    inner_output = arguments.output_directory.parent / (
        f".{arguments.output_directory.name}-inherited-{os.getpid()}"
    )
    if inner_output.exists() or inner_output.is_symlink():
        raise FollowupFormalNativeArtifactError("formal native inherited output exists")
    common = {
        "repository_root": arguments.repository_root,
        "lineage": lineage,
        "scratch_parent": arguments.scratch_parent,
        "output_directory": inner_output,
        "timeout_seconds_per_process": arguments.timeout_seconds_per_process,
        "resident_memory_limit_bytes": arguments.resident_memory_limit_bytes,
        "scratch_limit_bytes": arguments.scratch_limit_bytes,
        "scientific_profile": profile,
        "machine_plan_bytes": scientific.machine_plan_bytes,
        "case_plan": case,
    }
    try:
        if arguments.phase == "private-handoff":
            produce_route_a_native_qualification_handoff(**common)
        else:
            assert producer_inner is not None
            assert expected_q3_manifest is not None
            replay_and_guard_route_a_native_qualification(
                **common,
                q3_artifact_directory=producer_inner,
                expected_q3_manifest_sha256=expected_q3_manifest,
            )
        inspection = produce_followup_formal_native_artifact(
            inner_output,
            arguments.output_directory,
            phase=arguments.phase,
            repository_root=arguments.repository_root,
            lineage=lineage,
            scale=arguments.scale,
            formal_seed=arguments.formal_seed,
            strategy_candidate_id=arguments.strategy_candidate_id,
            scientific_profile=profile,
            machine_plan_bytes=scientific.machine_plan_bytes,
            unit_attempt_ordinal=arguments.unit_attempt_ordinal,
            producer_artifact_directory=(
                arguments.producer_artifact_directory
                if arguments.phase == "guarded-final"
                else None
            ),
        )
    finally:
        if inner_output.exists() and not inner_output.is_symlink():
            shutil.rmtree(inner_output, ignore_errors=True)
    print(
        json.dumps(
            {
                "artifact_name": inspection.artifact_name,
                "case_binding_sha256": inspection.case.case_binding_sha256,
                "inner_stage_manifest_sha256": inspection.inherited.manifest_sha256,
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
        FollowupFormalNativeArtifactError,
        OSError,
        RouteANativeQualificationError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
    ) as error:
        print(f"follow-up formal native execution failed closed: {error}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
