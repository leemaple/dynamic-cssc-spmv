#!/usr/bin/env python3
"""Dispatch one frozen formal-unit phase from its registered ordinal."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from dynamic_cssc.followup_performance_contract import (
    FollowupContractError,
    materialize_followup_scientific_plan,
)
from dynamic_cssc.followup_performance_formal_matrix import (
    FollowupFormalUnitSpec,
    followup_formal_unit_specs,
)
from scripts import run_followup_performance_acquisition as acquisition_cli
from scripts import run_followup_performance_formal_native as native_cli
from scripts import run_followup_performance_formal_ordered as ordered_cli
from scripts import run_followup_performance_formal_synthetic as synthetic_cli


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", required=True, choices=("private-handoff", "guarded-final"))
    parser.add_argument("--formal-unit-ordinal", required=True, type=int, choices=range(17))
    parser.add_argument("--expected-job-token", required=True)
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--experiment-source-sha", required=True)
    parser.add_argument("--workflow-head-sha", required=True)
    parser.add_argument("--compatibility-receipt-sha256", required=True)
    parser.add_argument("--provider-run-id", required=True, type=int)
    parser.add_argument("--provider-run-attempt", required=True, type=int, choices=(1,))
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--campaign-run-admission-sha256", required=True)
    parser.add_argument("--unit-attempt-ordinal", required=True, type=int, choices=(1, 2))
    parser.add_argument(
        "--acquisition-unit-attempt-ordinal",
        type=int,
        default=1,
        choices=(1, 2),
    )
    parser.add_argument("--scratch-root", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument("--producer-artifact-directory", type=Path)
    parser.add_argument("--acquisition-artifact-directory", type=Path)
    parser.add_argument("--acquisition-provider-run-id", type=int)
    parser.add_argument("--acquisition-provider-artifact-id", type=int)
    parser.add_argument("--acquisition-provider-artifact-digest")
    parser.add_argument("--acquisition-campaign-run-admission-sha256")
    return parser


def _common(arguments: argparse.Namespace) -> dict[str, object]:
    return {
        "compatibility_receipt_sha256": arguments.compatibility_receipt_sha256,
        "campaign_id": arguments.campaign_id,
        "campaign_run_admission_sha256": (
            arguments.campaign_run_admission_sha256
        ),
        "experiment_source_sha": arguments.experiment_source_sha,
        "formal_unit_ordinal": arguments.formal_unit_ordinal,
        "output_directory": arguments.output_directory,
        "phase": arguments.phase,
        "producer_artifact_directory": arguments.producer_artifact_directory,
        "provider_run_attempt": arguments.provider_run_attempt,
        "provider_run_id": arguments.provider_run_id,
        "repository_root": arguments.repository_root,
        "unit_attempt_ordinal": arguments.unit_attempt_ordinal,
        "workflow_head_sha": arguments.workflow_head_sha,
    }


def _dispatch(
    arguments: argparse.Namespace,
    spec: FollowupFormalUnitSpec,
) -> int:
    common = _common(arguments)
    if spec.unit_kind == "formal-acquisition":
        if arguments.acquisition_artifact_directory is not None:
            raise FollowupContractError("acquisition unit received an acquisition artifact")
        return acquisition_cli._main(
            argparse.Namespace(
                **common,
                scratch_root=arguments.scratch_root,
            )
        )
    if spec.unit_kind == "formal-native":
        if arguments.acquisition_artifact_directory is not None:
            raise FollowupContractError("native unit received an acquisition artifact")
        assert spec.scale is not None
        assert spec.formal_seed is not None
        assert spec.strategy_candidate_id is not None
        return native_cli._main(
            argparse.Namespace(
                **common,
                formal_seed=spec.formal_seed,
                resident_memory_limit_bytes=7 * 1024**3,
                scale=spec.scale,
                scratch_limit_bytes=8 * 1024**3,
                scratch_parent=arguments.scratch_root,
                strategy_candidate_id=spec.strategy_candidate_id,
                timeout_seconds_per_process=900,
            )
        )
    if spec.unit_kind == "formal-synthetic":
        if arguments.acquisition_artifact_directory is not None:
            raise FollowupContractError("synthetic unit received an acquisition artifact")
        assert spec.scale is not None
        assert spec.formal_seed is not None
        return synthetic_cli._main(
            argparse.Namespace(
                **common,
                formal_seed=spec.formal_seed,
                scale=spec.scale,
                scratch_root=arguments.scratch_root,
            )
        )
    if arguments.acquisition_artifact_directory is None:
        raise FollowupContractError("ordered-event unit lacks the admitted acquisition")
    if (
        arguments.acquisition_provider_run_id is None
        or arguments.acquisition_provider_artifact_id is None
        or arguments.acquisition_provider_artifact_digest is None
        or arguments.acquisition_campaign_run_admission_sha256 is None
    ):
        raise FollowupContractError(
            "ordered-event unit lacks the acquisition provider binding"
        )
    assert spec.partition is not None
    assert spec.semantics is not None
    return ordered_cli._main(
        argparse.Namespace(
            **common,
            acquisition_artifact_directory=arguments.acquisition_artifact_directory,
            acquisition_campaign_run_admission_sha256=(
                arguments.acquisition_campaign_run_admission_sha256
            ),
            acquisition_provider_artifact_digest=(
                arguments.acquisition_provider_artifact_digest
            ),
            acquisition_provider_artifact_id=(
                arguments.acquisition_provider_artifact_id
            ),
            acquisition_provider_run_id=arguments.acquisition_provider_run_id,
            acquisition_unit_attempt_ordinal=arguments.acquisition_unit_attempt_ordinal,
            partition=spec.partition,
            scratch_root=arguments.scratch_root,
            semantics=spec.semantics,
        )
    )


def _main(arguments: argparse.Namespace) -> int:
    paths = (
        arguments.repository_root,
        arguments.scratch_root,
        arguments.output_directory,
    )
    optional = (
        arguments.producer_artifact_directory,
        arguments.acquisition_artifact_directory,
    )
    if any(not path.is_absolute() for path in paths) or any(
        path is not None and not path.is_absolute() for path in optional
    ):
        raise FollowupContractError("formal unit paths must be absolute")
    if (arguments.phase == "private-handoff") == (
        arguments.producer_artifact_directory is not None
    ):
        raise FollowupContractError("formal unit phase and producer input disagree")
    scientific = materialize_followup_scientific_plan(arguments.repository_root)
    specs = followup_formal_unit_specs(scientific.scientific_profile)
    spec = specs[arguments.formal_unit_ordinal]
    if spec.ordinal != arguments.formal_unit_ordinal:
        raise AssertionError("formal unit ordinal projection changed")
    if spec.job_token != arguments.expected_job_token:
        raise FollowupContractError("formal workflow job token differs from the matrix")
    return _dispatch(arguments, spec)


def main() -> int:
    try:
        return _main(_parser().parse_args())
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        print(f"follow-up formal unit failed closed: {error}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
