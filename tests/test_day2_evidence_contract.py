from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_day2_raw_microbench_declares_isolated_profile_scope() -> None:
    source = (ROOT / "cpp" / "microbench.cpp").read_text(encoding="utf-8")

    assert "GetString" in source
    assert '"noise-budget-profile"' in source
    assert 'noiseBudgetProfile != "day2_mult_only"' in source
    assert "noise_budget_profile" in source
    assert "evidence_scope" in source
    assert "isolated-unit-probe-only" in source
    assert "mixed_workload_formal_parameter_claim_allowed" in source
    assert "false" in source


def test_day2_workflow_passes_the_isolated_multiplication_profile() -> None:
    workflow = (ROOT / ".github" / "workflows" / "day2-microbench.yml").read_text(
        encoding="utf-8"
    )

    assert "--noise-budget-profile day2_mult_only" in workflow
