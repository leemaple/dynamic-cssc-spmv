from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_missing_probe_layout_still_produces_a_failure_plan(tmp_path: Path) -> None:
    missing = tmp_path / "missing-layout.json"
    output = tmp_path / "logical-plan.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "make_logical_rotation_plan.py"),
            str(missing),
            str(output),
        ],
        check=False,
    )
    assert completed.returncode != 0
    payload = json.loads(output.read_text())
    assert payload["status"] == "p0a-probe-did-not-produce-layout"
    assert payload["plans"] == []
