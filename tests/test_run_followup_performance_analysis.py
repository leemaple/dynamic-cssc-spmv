from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.run_followup_performance_analysis as cli_module


def test_analysis_cli_reinspects_the_admitted_chain_at_exact_s3(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = (tmp_path / "repo").resolve()
    artifacts = (tmp_path / "artifacts").resolve()
    campaign_root = (tmp_path / "campaign").resolve()
    terminal_root = (tmp_path / "terminal").resolve()
    aggregate_root = (tmp_path / "aggregate").resolve()
    output_parent = (tmp_path / "output").resolve()
    for directory in (
        repository,
        artifacts,
        campaign_root,
        terminal_root,
        aggregate_root,
        output_parent,
    ):
        directory.mkdir()
    output = output_parent / "analysis"
    arguments = argparse.Namespace(
        repository_root=repository,
        experiment_source_sha="1" * 40,
        evidence_freeze_sha="2" * 40,
        analysis_source_sha="3" * 40,
        registration_compatibility_receipt_sha256="4" * 64,
        analysis_compatibility_receipt_sha256="5" * 64,
        terminal_provider_run_id=606,
        terminal_provider_run_attempt=1,
        campaign_evidence_root=campaign_root,
        formal_artifact_root=artifacts,
        terminal_artifact_directory=terminal_root,
        aggregate_artifact_directory=aggregate_root,
        output_directory=output,
    )
    compatibility = SimpleNamespace(
        document={"registration_compatibility_receipt_sha256": "4" * 64},
        sha256="5" * 64,
    )
    scientific = SimpleNamespace(
        scientific_profile=SimpleNamespace(profile_id="analysis-cli-sentinel"),
        machine_plan_bytes=b"sentinel-plan\n",
    )
    artifact_set = SimpleNamespace(sha256="6" * 64)
    timing = SimpleNamespace(sha256="7" * 64)
    selection = SimpleNamespace(
        document={
            "compatibility_receipt_sha256": "4" * 64,
            "evidence_freeze_S2_sha": "2" * 40,
            "experiment_source_S1_sha": "1" * 40,
        }
    )
    campaign = SimpleNamespace(selection=selection, timing=timing)
    terminal = SimpleNamespace(unit_identity_sha256="8" * 64)
    aggregate = SimpleNamespace(aggregate_sha256="9" * 64)
    observed: dict[str, object] = {}
    monkeypatch.setattr(cli_module, "_verify_exact_checkout", lambda *_args: None)
    monkeypatch.setattr(
        cli_module,
        "verify_followup_s1_s2_s3_analysis_compatibility",
        lambda *_args, **_kwargs: compatibility,
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
    monkeypatch.setattr(
        cli_module,
        "_timing_from_terminal",
        lambda path: observed.update({"timing_path": path}) or timing,
    )

    def inspect_terminal(path: Path, **kwargs: object) -> object:
        observed["terminal_path"] = path
        observed["terminal_set"] = kwargs["artifact_set"]
        observed["terminal_timing"] = kwargs["timing_ledger"]
        return terminal

    monkeypatch.setattr(
        cli_module,
        "inspect_followup_terminal_admission",
        inspect_terminal,
    )

    def inspect_aggregate(path: Path, **kwargs: object) -> object:
        observed["aggregate_path"] = path
        observed["aggregate_set"] = kwargs["artifact_set"]
        observed["aggregate_terminal"] = kwargs["terminal"]
        return aggregate

    monkeypatch.setattr(
        cli_module,
        "inspect_followup_aggregate",
        inspect_aggregate,
    )

    def produce(
        aggregate_input: object,
        compatibility_input: object,
        target: Path,
    ) -> object:
        observed["analysis_aggregate"] = aggregate_input
        observed["analysis_compatibility"] = compatibility_input
        observed["analysis_target"] = target
        return SimpleNamespace(
            analysis_sha256="a" * 64,
            artifact_name="followup-analysis-sentinel",
            unit_identity_sha256="b" * 64,
        )

    monkeypatch.setattr(cli_module, "produce_followup_analysis", produce)

    assert cli_module._main(arguments) == 0
    assert observed["timing_path"] == terminal_root
    assert observed["campaign_root"] == campaign_root
    assert observed["terminal_path"] == terminal_root
    assert observed["terminal_set"] is artifact_set
    assert observed["terminal_timing"] is timing
    assert observed["aggregate_path"] == aggregate_root
    assert observed["aggregate_set"] is artifact_set
    assert observed["aggregate_terminal"] is terminal
    assert observed["analysis_aggregate"] is aggregate
    assert observed["analysis_compatibility"] is compatibility
    assert observed["analysis_target"] == output
    assert '"artifact_name":"followup-analysis-sentinel"' in capsys.readouterr().out


def test_timing_loader_rejects_noncanonical_terminal_source(tmp_path: Path) -> None:
    terminal = (tmp_path / "terminal").resolve()
    terminal.mkdir()
    (terminal / "inner-payload.json").write_bytes(b'{"z":1, "a":2}\n')
    with pytest.raises(cli_module.FollowupAnalysisError, match="not canonical"):
        cli_module._timing_from_terminal(terminal)
