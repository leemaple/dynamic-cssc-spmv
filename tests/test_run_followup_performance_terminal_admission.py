from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.run_followup_performance_terminal_admission as cli_module


def test_terminal_cli_binds_timing_and_artifact_set_before_admission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = (tmp_path / "repo").resolve()
    artifacts = (tmp_path / "artifacts").resolve()
    campaign_root = (tmp_path / "campaign").resolve()
    output_parent = (tmp_path / "output").resolve()
    for directory in (repository, artifacts, campaign_root, output_parent):
        directory.mkdir()
    output = output_parent / "terminal"
    arguments = argparse.Namespace(
        repository_root=repository,
        experiment_source_sha="1" * 40,
        workflow_head_sha="2" * 40,
        compatibility_receipt_sha256="3" * 64,
        provider_run_id=505,
        provider_run_attempt=1,
        expected_head_branch="main",
        campaign_evidence_root=campaign_root,
        formal_artifact_root=artifacts,
        output_directory=output,
    )
    scientific = SimpleNamespace(
        scientific_profile=SimpleNamespace(profile_id="terminal-cli-sentinel"),
        machine_plan_bytes=b"sentinel-plan\n",
    )
    timing = SimpleNamespace(sha256="4" * 64)
    selection = SimpleNamespace(
        document={
            "compatibility_receipt_sha256": "3" * 64,
            "evidence_freeze_S2_sha": "2" * 40,
            "experiment_source_S1_sha": "1" * 40,
        }
    )
    campaign = SimpleNamespace(selection=selection, timing=timing)
    artifact_set = SimpleNamespace(sha256="5" * 64)
    observed: dict[str, object] = {}
    monkeypatch.setattr(cli_module, "_verify_exact_checkout", lambda *_args: None)
    monkeypatch.setattr(
        cli_module,
        "verify_followup_s1_s2_compatibility",
        lambda *_args, **_kwargs: SimpleNamespace(sha256="3" * 64),
    )
    monkeypatch.setattr(
        cli_module,
        "materialize_followup_scientific_plan",
        lambda _root: scientific,
    )
    monkeypatch.setattr(
        cli_module,
        "inspect_followup_campaign_evidence_bundle",
        lambda path, **_kwargs: (
            observed.update({"campaign_root": path}) or campaign
        ),
    )
    monkeypatch.setattr(
        cli_module,
        "inspect_followup_formal_artifact_set",
        lambda *_args, **_kwargs: artifact_set,
    )

    def produce(artifact_input: object, target: Path, **kwargs: object) -> object:
        observed["artifact_set"] = artifact_input
        observed["target"] = target
        observed["timing"] = kwargs["timing_ledger"]
        return SimpleNamespace(
            artifact_name="followup-terminal-sentinel",
            formal_artifact_set_sha256="5" * 64,
            formal_timing_ledger_sha256="4" * 64,
            unit_identity_sha256="6" * 64,
        )

    monkeypatch.setattr(cli_module, "produce_followup_terminal_admission", produce)

    assert cli_module._main(arguments) == 0
    assert observed["campaign_root"] == campaign_root
    assert observed["artifact_set"] is artifact_set
    assert observed["timing"] is timing
    assert observed["target"] == output
    assert '"artifact_name":"followup-terminal-sentinel"' in capsys.readouterr().out
