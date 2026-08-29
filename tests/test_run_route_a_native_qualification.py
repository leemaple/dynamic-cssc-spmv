from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.run_route_a_native_qualification as cli_module


def _arguments(tmp_path: Path, stage: str) -> list[str]:
    return [
        "run_route_a_native_qualification.py",
        "--stage",
        stage,
        "--repository-root",
        str((tmp_path / "repo").resolve()),
        "--experiment-source-sha",
        "1" * 40,
        "--workflow-head-sha",
        "2" * 40,
        "--compatibility-receipt-sha256",
        "3" * 64,
        "--provider-run-id",
        "17",
        "--provider-run-attempt",
        "1",
        "--scratch-parent",
        str((tmp_path / "scratch").resolve()),
        "--output-directory",
        str((tmp_path / "output").resolve()),
    ]


@pytest.mark.parametrize(
    "extra",
    (
        ("--q3-artifact-directory", "q3"),
        ("--expected-q3-manifest-sha256", "4" * 64),
    ),
)
def test_cli_q3_rejects_every_q4_only_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    extra: tuple[str, str],
) -> None:
    value = (
        str((tmp_path / extra[1]).resolve())
        if extra[0].endswith("directory")
        else extra[1]
    )
    monkeypatch.setattr(cli_module, "_verify_exact_checkout", lambda *_args: None)
    monkeypatch.setattr(sys, "argv", [*_arguments(tmp_path, "q3"), extra[0], value])

    assert cli_module.main() == 2
    assert "q3 cannot consume" in capsys.readouterr().err


def test_cli_q4_requires_both_artifact_and_externally_supplied_address(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli_module, "_verify_exact_checkout", lambda *_args: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            *_arguments(tmp_path, "q4"),
            "--q3-artifact-directory",
            str((tmp_path / "q3").resolve()),
        ],
    )

    assert cli_module.main() == 2
    assert "exact q3 artifact and expected q3 address" in capsys.readouterr().err


def test_cli_q4_passes_the_external_q3_address_to_the_stage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected = "4" * 64
    observed: dict[str, object] = {}
    monkeypatch.setattr(cli_module, "_verify_exact_checkout", lambda *_args: None)

    def run(**kwargs: object) -> SimpleNamespace:
        observed.update(kwargs)
        return SimpleNamespace(
            build_manifest_sha256="5" * 64,
            case_binding_sha256="6" * 64,
            input_q3_manifest_sha256=expected,
            manifest_sha256="7" * 64,
            stage="q4",
        )

    monkeypatch.setattr(cli_module, "replay_and_guard_route_a_native_qualification", run)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            *_arguments(tmp_path, "q4"),
            "--q3-artifact-directory",
            str((tmp_path / "q3").resolve()),
            "--expected-q3-manifest-sha256",
            expected,
        ],
    )

    assert cli_module.main() == 0
    assert observed["expected_q3_manifest_sha256"] == expected
    assert observed["q3_artifact_directory"] == (tmp_path / "q3").resolve()
    assert json.loads(capsys.readouterr().out) == {
        "authority_granted": False,
        "build_manifest_sha256": "5" * 64,
        "case_binding_sha256": "6" * 64,
        "input_q3_manifest_sha256_or_null": expected,
        "manifest_sha256": "7" * 64,
        "publication_evidence": False,
        "stage": "q4",
    }
