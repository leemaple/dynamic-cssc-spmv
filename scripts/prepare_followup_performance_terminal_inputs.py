#!/usr/bin/env python3
"""Install campaign evidence and fetch the exact seventeen selected artifacts."""

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
    install_followup_provider_artifact,
)
from dynamic_cssc.followup_performance_terminal import (
    inspect_followup_formal_artifact_set,
)


def _new_directory(path: Path, *, label: str) -> Path:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise FollowupCampaignControlError(f"{label} must be a new absolute path")
    parent = path.parent.resolve(strict=True)
    if parent.is_symlink() or not stat.S_ISDIR(parent.lstat().st_mode):
        raise FollowupCampaignControlError(f"{label} parent is not direct")
    path.mkdir(mode=0o700)
    return path


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
    return parser


def _main(arguments: argparse.Namespace) -> int:
    if arguments.repository.count("/") != 1:
        raise FollowupCampaignControlError("GitHub repository changed")
    scientific = materialize_followup_scientific_plan(arguments.repository_root)
    content = arguments.campaign_transport.read_bytes()
    transport = FollowupCampaignTransport(
        content=content,
        sha256=arguments.campaign_transport_sha256,
        member_count=arguments.campaign_transport_member_count,
        expanded_bytes=arguments.campaign_transport_expanded_bytes,
    )
    campaign = install_followup_campaign_transport(
        transport,
        arguments.campaign_evidence_output,
        scientific_profile=scientific.scientific_profile,
    )
    formal_root = _new_directory(
        arguments.formal_artifact_output,
        label="formal artifact output",
    )
    selection = campaign.selection.document
    expected_s2 = selection["evidence_freeze_S2_sha"]
    assert type(expected_s2) is str
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
            repository=arguments.repository,
            binding=FollowupProviderArtifactBinding(
                provider_artifact_id=artifact_id,
                artifact_name=artifact_name,
                provider_digest=artifact_digest,
            ),
            expected_run_id=provider_run_id,
            expected_head_sha=expected_s2,
            target_root=formal_root,
        )
    artifact_set = inspect_followup_formal_artifact_set(
        formal_root,
        repository_root=arguments.repository_root,
        campaign_selection=campaign.selection,
        scientific_profile=scientific.scientific_profile,
        machine_plan_bytes=scientific.machine_plan_bytes,
    )
    print(
        json.dumps(
            {
                "campaign_selection_sha256": campaign.selection.sha256,
                "formal_artifact_set_sha256": artifact_set.sha256,
                "formal_timing_ledger_sha256": campaign.timing.sha256,
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
        FollowupCampaignControlError,
        OSError,
        TypeError,
        ValueError,
        zipfile.BadZipFile,
    ) as error:
        print(f"follow-up terminal input preparation failed closed: {error}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
