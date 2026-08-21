from __future__ import annotations

import json
from pathlib import Path

from dynamic_cssc.cli import main


def test_smoke_cli_writes_predicted_only_artifacts(tmp_path: Path, monkeypatch) -> None:
    output = tmp_path / "out"
    monkeypatch.setattr(
        "sys.argv",
        [
            "dynamic-cssc",
            "smoke",
            "--output-dir",
            str(output),
            "--seed",
            "7",
            "--rows",
            "32",
            "--cols",
            "32",
            "--updates",
            "64",
            "--effective-slots",
            "128",
            "--partition-rows",
            "16",
        ],
    )
    assert main() == 0
    payload = json.loads((output / "metrics.json").read_text())
    assert payload["metadata"]["status"] == "predicted-proxy-not-measured"
    assert payload["metadata"]["gate_eligible"] is False
    assert payload["metadata"]["state_model"] == "static-initial-layout-proxy"
    assert any(record["strategy"] == "Mini-CSSC-Delta" for record in payload["records"])
    assert (output / "SHA256SUMS").exists()
