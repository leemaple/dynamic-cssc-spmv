from __future__ import annotations

from pathlib import Path

import pytest

from dynamic_cssc.followup_performance_contract import _canonical_json_bytes
from scripts.prepare_followup_performance_analysis_inputs import (
    prepare_analysis_inputs,
)


def _artifact(root: Path, name: str, content: bytes = b"sentinel\n") -> Path:
    artifact = root / name
    artifact.mkdir()
    (artifact / "member.txt").write_bytes(content)
    return artifact


def test_selector_materializes_only_the_terminal_admitted_set(tmp_path: Path) -> None:
    downloads = (tmp_path / "downloads").resolve()
    output_parent = (tmp_path / "output").resolve()
    downloads.mkdir()
    output_parent.mkdir()
    final_names = [
        f"followup-performance-v1-formal-synthetic-{ordinal:02d}"
        for ordinal in range(17)
    ]
    for name in final_names:
        _artifact(downloads, name)
    _artifact(downloads, "followup-performance-v1-formal-synthetic-private-handoff")
    terminal = _artifact(
        downloads,
        "followup-performance-v1-formal-terminal-admission-sentinel",
    )
    (terminal / "inner-payload.json").write_bytes(
        _canonical_json_bytes(
            {
                "artifacts": [
                    {"artifact_name": name, "ordinal": ordinal}
                    for ordinal, name in enumerate(final_names)
                ]
            }
        )
    )
    _artifact(downloads, "followup-performance-v1-formal-aggregate-sentinel")
    output = output_parent / "selected"

    receipt = prepare_analysis_inputs(downloads, output)

    assert receipt["formal_artifact_names"] == final_names
    assert {path.name for path in (output / "finals").iterdir()} == set(final_names)
    assert (output / "terminal" / "inner-payload.json").is_file()
    assert (output / "aggregate" / "member.txt").is_file()
    assert (output / "selection.json").is_file()


def test_selector_rejects_a_missing_admitted_artifact(tmp_path: Path) -> None:
    downloads = (tmp_path / "downloads").resolve()
    output_parent = (tmp_path / "output").resolve()
    downloads.mkdir()
    output_parent.mkdir()
    terminal = _artifact(
        downloads,
        "followup-performance-v1-formal-terminal-admission-sentinel",
    )
    (terminal / "inner-payload.json").write_bytes(
        _canonical_json_bytes(
            {
                "artifacts": [
                    {
                        "artifact_name": (
                            f"followup-performance-v1-formal-synthetic-{ordinal:02d}"
                        ),
                        "ordinal": ordinal,
                    }
                    for ordinal in range(17)
                ]
            }
        )
    )
    _artifact(downloads, "followup-performance-v1-formal-aggregate-sentinel")

    with pytest.raises(Exception, match="was not downloaded"):
        prepare_analysis_inputs(downloads, output_parent / "selected")
