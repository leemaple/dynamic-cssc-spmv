from __future__ import annotations

import re
from pathlib import Path

import pytest

from scripts import run_publication_structure_pilot as pilot_cli


def test_cli_passes_only_the_two_external_paths_to_the_public_producer(
    tmp_path: Path,
) -> None:
    calls: list[tuple[Path, Path]] = []

    def fake_producer(acquisition_bundle_root: Path, output_dir: Path) -> object:
        calls.append((acquisition_bundle_root, output_dir))
        return object()

    acquisition_root = tmp_path / "acquisition-bundles"
    output_dir = tmp_path / "NONADMISSIBLE-structure-pilot-test"

    assert (
        pilot_cli._run_cli(
            [
                "--acquisition-bundle-root",
                str(acquisition_root),
                "--output-dir",
                str(output_dir),
            ],
            producer=fake_producer,
        )
        == 0
    )
    assert calls == [(acquisition_root, output_dir)]


def test_cli_help_freezes_the_exact_two_path_only_options(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as completed:
        pilot_cli._parser().parse_args(["--help"])

    assert completed.value.code == 0
    help_text = capsys.readouterr().out
    assert set(re.findall(r"--[a-z][a-z0-9-]*", help_text)) == {
        "--help",
        "--acquisition-bundle-root",
        "--output-dir",
    }


@pytest.mark.parametrize(
    "forbidden_option",
    (
        "--dataset-id",
        "--semantics",
        "--source-partition",
        "--partition-mapping",
        "--prefix-fraction",
        "--rho",
        "--freshness-seconds",
        "--seed",
        "--config",
        "--candidate",
        "--source-sha",
        "--behavior-inventory",
        "--resource-policy",
        "--execution-adapter",
        "--publication-authority",
        "--admit-evidence",
        "--retry",
    ),
)
def test_cli_rejects_scientific_and_authority_parameters(
    tmp_path: Path,
    forbidden_option: str,
) -> None:
    with pytest.raises(SystemExit) as completed:
        pilot_cli._parser().parse_args(
            [
                "--acquisition-bundle-root",
                str(tmp_path / "acquisition-bundles"),
                "--output-dir",
                str(tmp_path / "NONADMISSIBLE-structure-pilot-test"),
                forbidden_option,
                "forged",
            ]
        )

    assert completed.value.code == 2


def test_cli_reports_hold_as_exit_two_without_creating_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output_dir = tmp_path / "NONADMISSIBLE-structure-pilot-missing"

    with pytest.raises(SystemExit) as completed:
        pilot_cli.main(
            [
                "--acquisition-bundle-root",
                str(tmp_path / "missing-acquisition-bundles"),
                "--output-dir",
                str(output_dir),
            ]
        )

    captured = capsys.readouterr()
    assert completed.value.code == 2
    assert captured.out == ""
    assert "HOLD" in captured.err
    assert not output_dir.exists()
