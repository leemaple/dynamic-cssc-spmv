#!/usr/bin/env python3
"""Reinspect the terminal-admitted set and emit one deterministic raw aggregate."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

from dynamic_cssc.followup_performance_aggregate import (
    FollowupAggregateError,
    produce_followup_aggregate,
)
from dynamic_cssc.followup_performance_campaign_bundle import (
    FollowupCampaignEvidenceBundleError,
    inspect_followup_campaign_evidence_bundle,
)
from dynamic_cssc.followup_performance_contract import (
    FollowupContractError,
    materialize_followup_scientific_plan,
)
from dynamic_cssc.followup_performance_lineage import (
    verify_followup_s1_s2_compatibility,
)
from dynamic_cssc.followup_performance_terminal import (
    FollowupTerminalAdmissionError,
    inspect_followup_formal_artifact_set,
    inspect_followup_terminal_admission,
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
        raise FollowupAggregateError(
            "aggregate requires a clean detached exact-S1 checkout"
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
    parser.add_argument("--campaign-evidence-root", required=True, type=Path)
    parser.add_argument("--formal-artifact-root", required=True, type=Path)
    parser.add_argument("--terminal-artifact-directory", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    return parser


def _main(arguments: argparse.Namespace) -> int:
    paths = (
        arguments.repository_root,
        arguments.campaign_evidence_root,
        arguments.formal_artifact_root,
        arguments.terminal_artifact_directory,
        arguments.output_directory,
    )
    if any(not path.is_absolute() for path in paths):
        raise FollowupAggregateError("aggregate paths must be absolute")
    _verify_exact_checkout(arguments.repository_root, arguments.experiment_source_sha)
    compatibility = verify_followup_s1_s2_compatibility(
        arguments.repository_root,
        s1=arguments.experiment_source_sha,
        s2=arguments.workflow_head_sha,
    )
    if compatibility.sha256 != arguments.compatibility_receipt_sha256:
        raise FollowupAggregateError("aggregate compatibility receipt changed")
    scientific = materialize_followup_scientific_plan(arguments.repository_root)
    lineage = RouteASyntheticSuiteLineage(
        experiment_source_sha=arguments.experiment_source_sha,
        workflow_head_sha=arguments.workflow_head_sha,
        compatibility_receipt_sha256=arguments.compatibility_receipt_sha256,
        provider_run_id=arguments.provider_run_id,
        provider_run_attempt=arguments.provider_run_attempt,
    )
    campaign = inspect_followup_campaign_evidence_bundle(
        arguments.campaign_evidence_root,
        scientific_profile=scientific.scientific_profile,
        expected_head_branch=arguments.expected_head_branch,
    )
    if (
        campaign.selection.document["experiment_source_S1_sha"]
        != arguments.experiment_source_sha
        or campaign.selection.document["evidence_freeze_S2_sha"]
        != arguments.workflow_head_sha
        or campaign.selection.document["compatibility_receipt_sha256"]
        != arguments.compatibility_receipt_sha256
    ):
        raise FollowupAggregateError("aggregate campaign evidence lineage changed")
    artifact_set = inspect_followup_formal_artifact_set(
        arguments.formal_artifact_root,
        repository_root=arguments.repository_root,
        campaign_selection=campaign.selection,
        scientific_profile=scientific.scientific_profile,
        machine_plan_bytes=scientific.machine_plan_bytes,
    )
    terminal = inspect_followup_terminal_admission(
        arguments.terminal_artifact_directory,
        artifact_set=artifact_set,
        campaign_selection=campaign.selection,
        lineage=lineage,
        timing_ledger=campaign.timing,
    )
    inspection = produce_followup_aggregate(
        artifact_set,
        terminal,
        arguments.output_directory,
        lineage=lineage,
    )
    print(
        json.dumps(
            {
                "aggregate_sha256": inspection.aggregate_sha256,
                "artifact_name": inspection.artifact_name,
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
        FollowupAggregateError,
        FollowupCampaignEvidenceBundleError,
        FollowupContractError,
        FollowupTerminalAdmissionError,
        OSError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
    ) as error:
        print(f"follow-up aggregate failed closed: {error}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
