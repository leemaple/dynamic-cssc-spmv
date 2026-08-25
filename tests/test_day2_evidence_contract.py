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
    assert "P0b and Day 2 OpenFHE exploratory microbench" in workflow
    assert "--stage Day2-exploratory" in workflow
    assert "name: day2-exploratory-${{ github.sha }}" in workflow
    assert "R3-Day2" not in workflow
    assert "r3-day2" not in workflow


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


def test_formal_probe_exports_only_evaluation_key_material_for_post_run_inventory() -> None:
    source = (ROOT / "cpp" / "microbench.cpp").read_text(encoding="utf-8")

    assert '"rotation-keys-output"' in source
    assert '"eval-mult-key-output"' in source
    assert "writeEvaluationKeyMaterial" in source
    assert "serializedRotationKeys_" in source
    assert "serializedEvalMultKeys_" in source
    assert "Serialize(keyPair_.secretKey" not in source


def test_formal_probe_measures_both_f1m_ciphertext_categories_from_fresh_encryption() -> (
    None
):
    source = (ROOT / "cpp" / "microbench.cpp").read_text(encoding="utf-8")

    assert "f1mRandomZeroSum_[0] = 1" in source
    assert "plaintextModulus_ - 1" in source
    assert "context_->Encrypt(keyPair_.publicKey, f1mRandomPlaintext)" in source
    assert "context_->Encrypt(keyPair_.publicKey, f1mDummyPlaintext)" in source
    assert "Serial::Serialize(f1mRandomZeroSumCiphertext_" in source
    assert "f1mEncryptedZeroDummyCiphertext_, f1mDummyStream" in source
    assert '\\"f1m_random_zero_sum_ciphertext_bytes\\"' in source
    assert '\\"f1m_encrypted_zero_dummy_ciphertext_bytes\\"' in source


def test_formal_probe_checks_exact_signed_rotation_not_merely_a_permutation() -> None:
    source = (ROOT / "cpp" / "microbench.cpp").read_text(encoding="utf-8")

    assert "IsExactFrozenLabelRotation" in source
    assert "rotationIndex" in source
    assert "rowSize = batchSize / 2" in source
    assert "rowOffset = (slot / rowSize) * rowSize" in source
    assert "values[slot] != expected" in source
    assert "IsFrozenLabelPermutation" not in source


def test_formal_probe_reports_affinity_observed_before_and_after_measurement() -> None:
    source = (ROOT / "cpp" / "microbench.cpp").read_text(encoding="utf-8")

    assert source.count("ProcessAffinityCpuList()") >= 2
    assert "process affinity changed during calibration" in source
    assert "process_affinity_cpu_list" in source


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
