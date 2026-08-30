#!/usr/bin/env python3
"""Run one formal SNAP ordered-event producer or independent replay."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

from dynamic_cssc.followup_performance_acquisition import (
    FollowupAcquisitionArtifactError,
    build_followup_acquisition_provider_binding,
    inspect_followup_acquisition_artifact,
)
from dynamic_cssc.followup_performance_contract import (
    FollowupContractError,
    followup_inherited_unit_attempt_ordinal,
    materialize_followup_scientific_plan,
)
from dynamic_cssc.followup_performance_formal_ordered_artifacts import (
    FollowupFormalOrderedArtifactError,
    inspect_followup_formal_ordered_artifact,
    produce_followup_formal_ordered_artifact,
)
from dynamic_cssc.followup_performance_lineage import (
    verify_followup_s1_s2_compatibility,
)
from dynamic_cssc.route_a_ordered_suite import (
    RouteAOrderedSuiteError,
    produce_route_a_ordered_suite_handoff,
    replay_and_guard_route_a_ordered_suite,
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
        raise FollowupFormalOrderedArtifactError(
            "formal ordered-event execution requires a clean detached exact-S1 checkout"
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
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--campaign-run-admission-sha256", required=True)
    parser.add_argument("--formal-unit-ordinal", required=True, type=int, choices=range(17))
    parser.add_argument("--acquisition-provider-run-id", required=True, type=int)
    parser.add_argument("--acquisition-provider-artifact-id", required=True, type=int)
    parser.add_argument("--acquisition-provider-artifact-digest", required=True)
    parser.add_argument(
        "--acquisition-campaign-run-admission-sha256",
        required=True,
    )
    parser.add_argument("--partition", required=True, type=int, choices=(0, 1))
    parser.add_argument("--semantics", required=True, choices=("T1", "T2"))
    parser.add_argument("--unit-attempt-ordinal", type=int, default=1, choices=(1, 2))
    parser.add_argument(
        "--acquisition-unit-attempt-ordinal",
        type=int,
        default=1,
        choices=(1, 2),
    )
    parser.add_argument("--scratch-root", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument("--acquisition-artifact-directory", required=True, type=Path)
    parser.add_argument("--producer-artifact-directory", type=Path)
    return parser


def _main(arguments: argparse.Namespace) -> int:
    paths = (
        arguments.repository_root,
        arguments.scratch_root,
        arguments.output_directory,
        arguments.acquisition_artifact_directory,
    )
    if any(not path.is_absolute() for path in paths) or (
        arguments.producer_artifact_directory is not None
        and not arguments.producer_artifact_directory.is_absolute()
    ):
        raise FollowupFormalOrderedArtifactError(
            "formal ordered-event paths must be absolute"
        )
    _verify_exact_checkout(arguments.repository_root, arguments.experiment_source_sha)
    compatibility = verify_followup_s1_s2_compatibility(
        arguments.repository_root,
        s1=arguments.experiment_source_sha,
        s2=arguments.workflow_head_sha,
    )
    if compatibility.sha256 != arguments.compatibility_receipt_sha256:
        raise FollowupFormalOrderedArtifactError(
            "formal ordered-event compatibility receipt changed"
        )
    scientific = materialize_followup_scientific_plan(arguments.repository_root)
    profile = scientific.scientific_profile
    lineage = RouteASyntheticSuiteLineage(
        experiment_source_sha=arguments.experiment_source_sha,
        workflow_head_sha=arguments.workflow_head_sha,
        compatibility_receipt_sha256=arguments.compatibility_receipt_sha256,
        provider_run_id=arguments.provider_run_id,
        provider_run_attempt=arguments.provider_run_attempt,
    )
    acquisition_lineage = RouteASyntheticSuiteLineage(
        experiment_source_sha=arguments.experiment_source_sha,
        workflow_head_sha=arguments.workflow_head_sha,
        compatibility_receipt_sha256=arguments.compatibility_receipt_sha256,
        provider_run_id=arguments.acquisition_provider_run_id,
        provider_run_attempt=1,
    )
    acquisition = inspect_followup_acquisition_artifact(
        arguments.acquisition_artifact_directory,
        phase="guarded-final",
        lineage=acquisition_lineage,
        campaign_id=arguments.campaign_id,
        campaign_run_admission_sha256=(
            arguments.acquisition_campaign_run_admission_sha256
        ),
        formal_unit_ordinal=0,
        unit_attempt_ordinal=arguments.acquisition_unit_attempt_ordinal,
    )
    acquisition_binding = build_followup_acquisition_provider_binding(
        acquisition,
        artifact_id=arguments.acquisition_provider_artifact_id,
        artifact_provider_digest=arguments.acquisition_provider_artifact_digest,
    )
    matches = tuple(
        trace
        for trace in acquisition.traces
        if trace.partition == arguments.partition and trace.semantics == arguments.semantics
    )
    if len(matches) != 1:
        raise FollowupFormalOrderedArtifactError(
            "formal acquisition lacks one exact ordered-event trace"
        )
    trace = matches[0]
    inherited_attempt = followup_inherited_unit_attempt_ordinal(
        unit_kind="formal-ordered-event",
        unit_attempt_ordinal=arguments.unit_attempt_ordinal,
    )
    payload_path = arguments.output_directory.parent / (
        f".{arguments.output_directory.name}-payload-{os.getpid()}.zip"
    )
    if payload_path.exists() or payload_path.is_symlink():
        raise FollowupFormalOrderedArtifactError(
            "formal ordered-event temporary payload already exists"
        )
    try:
        if arguments.phase == "private-handoff":
            if arguments.producer_artifact_directory is not None:
                raise FollowupFormalOrderedArtifactError(
                    "formal ordered producer received a producer artifact"
                )
            produce_route_a_ordered_suite_handoff(
                trace,
                lineage=lineage,
                machine_plan_bytes=scientific.machine_plan_bytes,
                scratch_root=arguments.scratch_root,
                output_path=payload_path,
                unit_attempt_ordinal=inherited_attempt,
                scientific_profile=profile,
            )
        else:
            if arguments.producer_artifact_directory is None:
                raise FollowupFormalOrderedArtifactError(
                    "formal ordered replay lacks its producer artifact"
                )
            producer = inspect_followup_formal_ordered_artifact(
                arguments.producer_artifact_directory,
                phase="private-handoff",
                trace=trace,
                lineage=lineage,
                scientific_profile=profile,
                machine_plan_bytes=scientific.machine_plan_bytes,
                campaign_id=arguments.campaign_id,
                campaign_run_admission_sha256=(
                    arguments.campaign_run_admission_sha256
                ),
                formal_unit_ordinal=arguments.formal_unit_ordinal,
                acquisition_provider_binding_sha256=acquisition_binding.sha256,
                unit_attempt_ordinal=arguments.unit_attempt_ordinal,
            )
            replay_and_guard_route_a_ordered_suite(
                trace,
                lineage=lineage,
                machine_plan_bytes=scientific.machine_plan_bytes,
                producer_archive_path=producer.payload_path,
                scratch_root=arguments.scratch_root,
                output_path=payload_path,
                unit_attempt_ordinal=inherited_attempt,
                scientific_profile=profile,
            )
        inspection = produce_followup_formal_ordered_artifact(
            payload_path,
            arguments.output_directory,
            phase=arguments.phase,
            trace=trace,
            lineage=lineage,
            scientific_profile=profile,
            machine_plan_bytes=scientific.machine_plan_bytes,
            campaign_id=arguments.campaign_id,
            campaign_run_admission_sha256=arguments.campaign_run_admission_sha256,
            formal_unit_ordinal=arguments.formal_unit_ordinal,
            acquisition_provider_binding_sha256=acquisition_binding.sha256,
            unit_attempt_ordinal=arguments.unit_attempt_ordinal,
        )
    finally:
        if payload_path.exists() and not payload_path.is_symlink():
            payload_path.unlink()
    print(
        json.dumps(
            {
                "artifact_name": inspection.artifact_name,
                "inner_payload_sha256": inspection.payload_sha256,
                "partition": trace.partition,
                "semantics": trace.semantics,
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
        FollowupAcquisitionArtifactError,
        FollowupContractError,
        FollowupFormalOrderedArtifactError,
        OSError,
        RouteAOrderedSuiteError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
    ) as error:
        print(f"follow-up formal ordered execution failed closed: {error}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
