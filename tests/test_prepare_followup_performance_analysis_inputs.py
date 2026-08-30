from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.prepare_followup_performance_analysis_inputs as preparation
from dynamic_cssc.followup_performance_campaign_controller import (
    FollowupCampaignControlError,
)
from dynamic_cssc.followup_performance_campaign_transport import (
    FollowupCampaignTransport,
)
from dynamic_cssc.followup_performance_provider_artifacts import (
    FollowupProviderArtifactBinding,
)


def _terminal() -> FollowupProviderArtifactBinding:
    return FollowupProviderArtifactBinding(
        provider_artifact_id=91_001,
        artifact_name=(
            "followup-performance-v1-formal-terminal-admission-sentinel"
        ),
        provider_digest=f"sha256:{'a' * 64}",
        size_in_bytes_or_null=101,
    )


def _aggregate() -> FollowupProviderArtifactBinding:
    return FollowupProviderArtifactBinding(
        provider_artifact_id=91_002,
        artifact_name="followup-performance-v1-formal-aggregate-sentinel",
        provider_digest=f"sha256:{'b' * 64}",
        size_in_bytes_or_null=202,
    )


def test_preparation_installs_seventeen_selected_and_two_terminal_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b"campaign-transport"
    transport = FollowupCampaignTransport(
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        member_count=190,
        expanded_bytes=2_000_000,
    )
    units = tuple(
        {
            "artifact_id": 80_000 + ordinal,
            "artifact_name": (
                f"followup-performance-v1-formal-synthetic-{ordinal:02d}"
            ),
            "artifact_provider_digest": f"sha256:{ordinal + 1:064x}",
            "provider_run_id": 70_000 + ordinal,
        }
        for ordinal in range(17)
    )
    campaign = SimpleNamespace(
        selection=SimpleNamespace(
            document={"evidence_freeze_S2_sha": "2" * 40},
            sha256="3" * 64,
            units=units,
        ),
        timing=SimpleNamespace(sha256="4" * 64),
    )
    monkeypatch.setattr(
        preparation,
        "materialize_followup_scientific_plan",
        lambda _root: SimpleNamespace(
            scientific_profile=object(), machine_plan_bytes=b"plan"
        ),
    )
    monkeypatch.setattr(
        preparation,
        "install_followup_campaign_transport",
        lambda *_args, **_kwargs: campaign,
    )
    installed: list[tuple[int, int, str]] = []

    def install(**kwargs):  # type: ignore[no-untyped-def]
        binding = kwargs["binding"]
        root = kwargs["target_root"]
        path = root / binding.artifact_name
        path.mkdir()
        installed.append(
            (
                binding.provider_artifact_id,
                kwargs["expected_run_id"],
                kwargs["expected_head_sha"],
            )
        )
        return path

    monkeypatch.setattr(preparation, "install_followup_provider_artifact", install)
    monkeypatch.setattr(
        preparation,
        "inspect_followup_formal_artifact_set",
        lambda *_args, **_kwargs: SimpleNamespace(sha256="5" * 64),
    )
    for name in ("campaign", "formal", "terminal"):
        (tmp_path / f"{name}-parent").mkdir()

    receipt = preparation.prepare_analysis_inputs(
        repository_root=tmp_path,
        repository="example/project",
        campaign_transport=transport,
        campaign_evidence_output=(tmp_path / "campaign-parent/campaign").resolve(),
        formal_artifact_output=(tmp_path / "formal-parent/formal").resolve(),
        terminal_artifact_output=(tmp_path / "terminal-parent/terminal").resolve(),
        terminal_provider_run_id=90_001,
        terminal_artifact=_terminal(),
        aggregate_artifact=_aggregate(),
        artifact_transport=object(),  # type: ignore[arg-type]
    )

    assert len(installed) == 19
    assert installed[:17] == [
        (80_000 + ordinal, 70_000 + ordinal, "2" * 40)
        for ordinal in range(17)
    ]
    assert installed[-2:] == [
        (91_001, 90_001, "2" * 40),
        (91_002, 90_001, "2" * 40),
    ]
    assert receipt == {
        "aggregate_artifact_name": _aggregate().artifact_name,
        "campaign_selection_sha256": "3" * 64,
        "formal_artifact_count": 17,
        "formal_artifact_set_sha256": "5" * 64,
        "formal_timing_ledger_sha256": "4" * 64,
        "terminal_artifact_name": _terminal().artifact_name,
        "terminal_provider_run_id": 90_001,
    }


def test_preparation_rejects_swapped_terminal_roles(tmp_path: Path) -> None:
    with pytest.raises(
        FollowupCampaignControlError,
        match="terminal artifact bindings",
    ):
        preparation.prepare_analysis_inputs(
            repository_root=tmp_path,
            repository="example/project",
            campaign_transport=FollowupCampaignTransport(
                content=b"sentinel",
                sha256=hashlib.sha256(b"sentinel").hexdigest(),
                member_count=1,
                expanded_bytes=1,
            ),
            campaign_evidence_output=tmp_path / "campaign",
            formal_artifact_output=tmp_path / "formal",
            terminal_artifact_output=tmp_path / "terminal",
            terminal_provider_run_id=90_001,
            terminal_artifact=_aggregate(),
            aggregate_artifact=_terminal(),
        )
