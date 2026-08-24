from __future__ import annotations

import re
from pathlib import Path

from dynamic_cssc.publication_statistics import (
    PRIMITIVE_NAMES,
    calibration_operation_order,
)

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


def test_day2_probe_emits_the_frozen_raw_block_contract() -> None:
    source = (ROOT / "cpp" / "microbench.cpp").read_text(encoding="utf-8")

    assert "dynamic-cssc-day2-raw-block-probe-v1" in source
    assert "dynamic-cssc-publication-raw-measurement-blocks-v1" in source
    assert "kPrimitiveCount = 14" in source
    assert "kFrozenBlockCount = 14" in source
    assert "warmups == 3 && repetitions == 14" in source
    assert "exactly-14-whole-blocks-outcome-independent-no-optional-stopping" in source
    assert "elapsed_ns" in source
    assert "operation_count" in source
    assert "std::chrono::steady_clock" in source


def test_day2_probe_hardcoded_orders_match_every_frozen_sampler_answer() -> None:
    source = (ROOT / "cpp" / "microbench.cpp").read_text(encoding="utf-8")
    table_start = source.index(
        "constexpr std::array<OperationOrder, kFrozenBlockCount> kOperationOrders"
    )
    table_end = source.index("}};", table_start)
    names = re.findall(r'"([a-z_]+)"', source[table_start:table_end])

    primitive_count = len(PRIMITIVE_NAMES)
    assert len(names) == 14 * primitive_count
    rows = [
        tuple(names[offset : offset + primitive_count])
        for offset in range(0, len(names), primitive_count)
    ]
    assert rows == [calibration_operation_order(block) for block in range(14)]
