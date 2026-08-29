from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.control_route_a_publication as controller_cli
import scripts.run_route_a_combined_guard as q5_cli
import scripts.run_route_a_postrun_admission as q6_cli
import scripts.verify_route_a_qualification_lineage as lineage_cli


def test_external_controller_cli_wires_the_exact_stop_loss_without_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    observed: dict[str, object] = {}

    def provider(**kwargs: object) -> SimpleNamespace:
        observed["provider"] = kwargs
        return SimpleNamespace()

    def watch(
        _provider: object,
        request: object,
        *,
        poll_interval_seconds: int,
    ) -> SimpleNamespace:
        observed["request"] = request
        observed["poll_interval_seconds"] = poll_interval_seconds
        return SimpleNamespace(
            decision="combined-guard-success-before-threshold",
            document={
                "decision": "combined-guard-success-before-threshold",
                "formal_execution_authorized": False,
            },
        )

    monkeypatch.setenv("GITHUB_TOKEN", "secret-token")
    monkeypatch.setattr(controller_cli, "GitHubActionsQualificationProvider", provider)
    monkeypatch.setattr(controller_cli, "watch_route_a_qualification", watch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "control_route_a_publication.py",
            "--repository-root",
            str(tmp_path.resolve()),
            "--repository",
            "owner/repository",
            "--run-id",
            "41",
            "--expected-s2",
            "2" * 40,
            "--watch-stop-loss",
            "--poll-interval-seconds",
            "7",
        ],
    )

    assert controller_cli.main() == 0
    request = observed["request"]
    assert request.run_id == 41  # type: ignore[attr-defined]
    assert request.expected_s2_git_sha == "2" * 40  # type: ignore[attr-defined]
    assert observed["poll_interval_seconds"] == 7
    assert json.loads(capsys.readouterr().out) == {
        "decision": "combined-guard-success-before-threshold",
        "formal_execution_authorized": False,
    }


def test_q5_cli_passes_exact_provider_wrapper_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    observed: dict[str, object] = {}
    monkeypatch.setattr(q5_cli, "_verify_exact_checkout", lambda *_args: None)

    def produce(**kwargs: object) -> SimpleNamespace:
        observed.update(kwargs)
        return SimpleNamespace(
            manifest_sha256="7" * 64,
            q2_provider=SimpleNamespace(digest="sha256:" + "8" * 64),
            q4_provider=SimpleNamespace(digest="sha256:" + "9" * 64),
        )

    monkeypatch.setattr(q5_cli, "produce_route_a_combined_guard", produce)
    arguments = [
        "run_route_a_combined_guard.py",
        "--repository-root",
        str((tmp_path / "repo").resolve()),
        "--experiment-source-sha",
        "1" * 40,
        "--workflow-head-sha",
        "2" * 40,
        "--compatibility-receipt-sha256",
        "3" * 64,
        "--provider-run-id",
        "41",
        "--provider-run-attempt",
        "1",
        "--provider-artifacts-json",
        str((tmp_path / "provider.json").resolve()),
        "--q2-wrapper",
        str((tmp_path / "q2.zip").resolve()),
        "--q4-wrapper",
        str((tmp_path / "q4.zip").resolve()),
        "--scratch-parent",
        str((tmp_path / "scratch").resolve()),
        "--output-directory",
        str((tmp_path / "out").resolve()),
    ]
    monkeypatch.setattr(sys, "argv", arguments)

    assert q5_cli.main() == 0
    assert observed["q2_wrapper_path"] == (tmp_path / "q2.zip").resolve()
    assert observed["q4_wrapper_path"] == (tmp_path / "q4.zip").resolve()
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["stage"] == "q5"
    assert receipt["formal_execution_authorized"] is False


def test_q6_cli_passes_only_provider_snapshots_and_exact_run_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    observed: dict[str, object] = {}
    monkeypatch.setattr(q6_cli, "_verify_exact_checkout", lambda *_args: None)

    def produce(**kwargs: object) -> SimpleNamespace:
        observed.update(kwargs)
        return SimpleNamespace(record_sha256="4" * 64)

    monkeypatch.setattr(q6_cli, "produce_route_a_postrun_admission", produce)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_route_a_postrun_admission.py",
            "--repository-root",
            str((tmp_path / "repo").resolve()),
            "--experiment-source-sha",
            "1" * 40,
            "--expected-s2-git-sha",
            "2" * 40,
            "--expected-head-branch",
            "main",
            "--expected-run-id",
            "41",
            "--expected-run-attempt",
            "1",
            "--run-json",
            str((tmp_path / "run.json").resolve()),
            "--jobs-json",
            str((tmp_path / "jobs.json").resolve()),
            "--artifacts-json",
            str((tmp_path / "artifacts.json").resolve()),
            "--output-directory",
            str((tmp_path / "q6").resolve()),
        ],
    )

    assert q6_cli.main() == 0
    assert observed["expected_run_id"] == 41
    assert observed["expected_run_attempt"] == 1
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["stage"] == "q6"
    assert receipt["formal_execution_authorized"] is False


def test_lineage_cli_requires_the_external_expected_receipt_address(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected = "3" * 64
    monkeypatch.setattr(
        lineage_cli,
        "verify_route_a_s1_s2_compatibility",
        lambda *_args, **_kwargs: SimpleNamespace(sha256=expected),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "verify_route_a_qualification_lineage.py",
            "--repository-root",
            str(tmp_path.resolve()),
            "--s1",
            "1" * 40,
            "--s2",
            "2" * 40,
            "--expected-receipt-sha256",
            expected,
        ],
    )

    assert lineage_cli.main() == 0
    assert json.loads(capsys.readouterr().out)["compatibility_receipt_sha256"] == expected
