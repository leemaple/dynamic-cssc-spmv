from __future__ import annotations

from pathlib import Path


def test_day1_workflow_guards_the_causal_evidence_contract() -> None:
    workflow = (Path(__file__).parents[1] / ".github/workflows/day1-cost-model.yml").read_text(
        encoding="utf-8"
    )

    assert "p['status']" not in workflow
    assert "inputs.updates" not in workflow
    assert "assert p['schema'] == 'day1-causal-predicted-v1'" in workflow
    assert "assert p['state_model'] == 'persistent-strategy-snapshots'" in workflow
    assert "assert p['measurement_kind'] == 'predicted-proxy'" in workflow
    assert "assert p['gate_eligible'] is False" in workflow
    assert "assert p['complete_cost_claim_allowed'] is False" in workflow
