from __future__ import annotations

from pathlib import Path

from dynamic_cssc.manifest import load_manifest
from dynamic_cssc.preflight import run_day1_preflight

ROOT = Path(__file__).resolve().parents[1]


def test_required_preflight_uses_global_ci_and_multiple_output_blocks() -> None:
    manifest = load_manifest(ROOT / "config" / "params_manifest.json")

    report = run_day1_preflight(manifest)

    assert report.status == "pass"
    assert report.rows == 257
    assert report.cols == 521
    assert report.effective_slots == 256
    assert report.output_shares == 2
    assert report.observed_global_column_index == 520
    assert report.modulo_alias_column_index == 8
    assert report.global_gather_value == 1
    assert report.modulo_alias_value == 0
    assert report.reconstructed_matches_direct
    assert report.reconstructed_high_row_value == 1
