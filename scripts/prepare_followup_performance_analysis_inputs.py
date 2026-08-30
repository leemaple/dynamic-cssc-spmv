#!/usr/bin/env python3
"""Install the exact campaign, formal, terminal, and aggregate analysis inputs."""

from __future__ import annotations

import argparse
import json
import os
import stat
import zipfile
from pathlib import Path

from dynamic_cssc.followup_performance_campaign_controller import (
    FollowupCampaignControlError,
)
from dynamic_cssc.followup_performance_campaign_transport import (
    FollowupCampaignTransport,
    install_followup_campaign_transport,
)
from dynamic_cssc.followup_performance_contract import (
    materialize_followup_scientific_plan,
)
from dynamic_cssc.followup_performance_provider_artifacts import (
    FollowupProviderArtifactBinding,
    FollowupProviderArtifactTransport,
    GitHubCliArtifactTransport,
    install_followup_provider_artifact,
)
from dynamic_cssc.followup_performance_terminal import (
    inspect_followup_formal_artifact_set,
)

_TERMINAL_PREFIX = "followup-performance-v1-formal-terminal-admission-"
_AGGREGATE_PREFIX = "followup-performance-v1-formal-aggregate-"


def _new_directory(path: Path, *, label: str) -> Path:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise FollowupCampaignControlError(f"{label} must be a new absolute path")
    parent = path.parent.resolve(strict=True)
    if parent.is_symlink() or not stat.S_ISDIR(parent.lstat().st_mode):
        raise FollowupCampaignControlError(f"{label} parent is not direct")
    path.mkdir(mode=0o700)
    return path


def prepare_analysis_inputs(
    *,
    repository_root: Path,
    repository: str,
    campaign_transport: FollowupCampaignTransport,
    campaign_evidence_output: Path,
    formal_artifact_output: Path,
    terminal_artifact_output: Path,
    terminal_provider_run_id: int,
    terminal_artifact: FollowupProviderArtifactBinding,
    aggregate_artifact: FollowupProviderArtifactBinding,
    artifact_transport: FollowupProviderArtifactTransport | None = None,
) -> dict[str, object]:
    """Install and deeply rebind every input needed by the S3 analyzer."""

    if (
        not terminal_artifact.artifact_name.startswith(_TERMINAL_PREFIX)
        or not aggregate_artifact.artifact_name.startswith(_AGGREGATE_PREFIX)
        or terminal_artifact.provider_artifact_id
        == aggregate_artifact.provider_artifact_id
    ):
        raise FollowupCampaignControlError(
            "analysis terminal artifact bindings changed"
        )
    scientific = materialize_followup_scientific_plan(repository_root)
    campaign = install_followup_campaign_transport(
        campaign_transport,
        campaign_evidence_output,
        scientific_profile=scientific.scientific_profile,
    )
    formal_root = _new_directory(
        formal_artifact_output,
        label="formal artifact output",
    )
    terminal_root = _new_directory(
        terminal_artifact_output,
        label="terminal artifact output",
    )
    selection = campaign.selection.document
    expected_s2 = selection["evidence_freeze_S2_sha"]
    if type(expected_s2) is not str:
        raise FollowupCampaignControlError("campaign selection S2 changed")
    adapter = artifact_transport or GitHubCliArtifactTransport()
    for selected in campaign.selection.units:
        artifact_id = selected.get("artifact_id")
        artifact_name = selected.get("artifact_name")
        artifact_digest = selected.get("artifact_provider_digest")
        provider_run_id = selected.get("provider_run_id")
        if (
            type(artifact_id) is not int
            or type(artifact_name) is not str
            or type(artifact_digest) is not str
            or type(provider_run_id) is not int
        ):
            raise FollowupCampaignControlError(
                "campaign selection artifact identity changed"
            )
        install_followup_provider_artifact(
            repository=repository,
            binding=FollowupProviderArtifactBinding(
                provider_artifact_id=artifact_id,
                artifact_name=artifact_name,
                provider_digest=artifact_digest,
            ),
            expected_run_id=provider_run_id,
            expected_head_sha=expected_s2,
            target_root=formal_root,
            transport=adapter,
        )
    artifact_set = inspect_followup_formal_artifact_set(
        formal_root,
        repository_root=repository_root,
        campaign_selection=campaign.selection,
        scientific_profile=scientific.scientific_profile,
        machine_plan_bytes=scientific.machine_plan_bytes,
    )
    terminal_path = install_followup_provider_artifact(
        repository=repository,
        binding=terminal_artifact,
        expected_run_id=terminal_provider_run_id,
        expected_head_sha=expected_s2,
        target_root=terminal_root,
        transport=adapter,
    )
    aggregate_path = install_followup_provider_artifact(
        repository=repository,
        binding=aggregate_artifact,
        expected_run_id=terminal_provider_run_id,
        expected_head_sha=expected_s2,
        target_root=terminal_root,
        transport=adapter,
    )
    return {
        "aggregate_artifact_name": aggregate_path.name,
        "campaign_selection_sha256": campaign.selection.sha256,
        "formal_artifact_count": len(campaign.selection.units),
        "formal_artifact_set_sha256": artifact_set.sha256,
        "formal_timing_ledger_sha256": campaign.timing.sha256,
        "terminal_artifact_name": terminal_path.name,
        "terminal_provider_run_id": terminal_provider_run_id,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--campaign-transport", required=True, type=Path)
    parser.add_argument("--campaign-transport-sha256", required=True)
    parser.add_argument("--campaign-transport-member-count", required=True, type=int)
    parser.add_argument("--campaign-transport-expanded-bytes", required=True, type=int)
    parser.add_argument("--campaign-evidence-output", required=True, type=Path)
    parser.add_argument("--formal-artifact-output", required=True, type=Path)
    parser.add_argument("--terminal-artifact-output", required=True, type=Path)
    parser.add_argument("--terminal-provider-run-id", required=True, type=int)
    parser.add_argument("--terminal-artifact-id", required=True, type=int)
    parser.add_argument("--terminal-artifact-name", required=True)
    parser.add_argument("--terminal-artifact-provider-digest", required=True)
    parser.add_argument("--terminal-artifact-size", required=True, type=int)
    parser.add_argument("--aggregate-artifact-id", required=True, type=int)
    parser.add_argument("--aggregate-artifact-name", required=True)
    parser.add_argument("--aggregate-artifact-provider-digest", required=True)
    parser.add_argument("--aggregate-artifact-size", required=True, type=int)
    return parser


def _main(arguments: argparse.Namespace) -> int:
    content = arguments.campaign_transport.read_bytes()
    receipt = prepare_analysis_inputs(
        repository_root=arguments.repository_root,
        repository=arguments.repository,
        campaign_transport=FollowupCampaignTransport(
            content=content,
            sha256=arguments.campaign_transport_sha256,
            member_count=arguments.campaign_transport_member_count,
            expanded_bytes=arguments.campaign_transport_expanded_bytes,
        ),
        campaign_evidence_output=arguments.campaign_evidence_output,
        formal_artifact_output=arguments.formal_artifact_output,
        terminal_artifact_output=arguments.terminal_artifact_output,
        terminal_provider_run_id=arguments.terminal_provider_run_id,
        terminal_artifact=FollowupProviderArtifactBinding(
            provider_artifact_id=arguments.terminal_artifact_id,
            artifact_name=arguments.terminal_artifact_name,
            provider_digest=arguments.terminal_artifact_provider_digest,
            size_in_bytes_or_null=arguments.terminal_artifact_size,
        ),
        aggregate_artifact=FollowupProviderArtifactBinding(
            provider_artifact_id=arguments.aggregate_artifact_id,
            artifact_name=arguments.aggregate_artifact_name,
            provider_digest=arguments.aggregate_artifact_provider_digest,
            size_in_bytes_or_null=arguments.aggregate_artifact_size,
        ),
    )
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


def main() -> int:
    try:
        return _main(_parser().parse_args())
    except (
        FollowupCampaignControlError,
        OSError,
        TypeError,
        ValueError,
        zipfile.BadZipFile,
    ) as error:
        print(
            f"follow-up analysis input preparation failed closed: {error}",
            file=os.sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
