from __future__ import annotations

import json
from pathlib import Path

from scripts.run_day1_suite import load_experiment_plan

ROOT = Path(__file__).parents[1]


def test_day1_workflow_guards_the_causal_evidence_contract() -> None:
    workflow = (ROOT / ".github/workflows/day1-cost-model.yml").read_text(encoding="utf-8")

    assert "p['status']" not in workflow
    assert "inputs.updates" not in workflow
    assert "assert p['schema'] == 'day1-causal-predicted-v1'" in workflow
    assert "assert p['state_model'] == 'persistent-strategy-snapshots'" in workflow
    assert "assert p['measurement_kind'] == 'predicted-proxy'" in workflow
    assert "assert p['gate_eligible'] is False" in workflow
    assert "assert p['complete_cost_claim_allowed'] is False" in workflow
    assert "assert p['complete_reference_set'] is False" in workflow
    assert "assert p['suite_complete'] is True" in workflow
    assert workflow.count("assert p['experiment_plan_version'] == '0.2.0'") == 2
    assert workflow.count("assert p['effective_slots'] == 2048") == 2
    assert workflow.count("assert p['partition_rows'] == 128") == 2
    assert workflow.count("assert p['layout_measurement_kind'] == 'synthetic-proxy'") == 2
    assert (
        "assert p['deferred_unpriced_plan_dimensions'] == ['bandwidth_profiles_mbps']" in workflow
    )
    assert "assert p['preflight']['status'] == 'pass'" in workflow


def test_dispatch_seed_is_normalized_once_from_env_before_any_use() -> None:
    workflow = (ROOT / ".github/workflows/day1-cost-model.yml").read_text(encoding="utf-8")

    assert workflow.count("${{ inputs.seed }}") == 1
    assert "RAW_SEED: ${{ inputs.seed }}" in workflow
    assert "parse_canonical_seed(os.environ['RAW_SEED'])" in workflow
    assert "normalized_seed: ${{ steps.normalize-seed.outputs.normalized_seed }}" in workflow
    assert "--seed '${{ needs.plan.outputs.normalized_seed }}'" in workflow
    assert (
        "name: r2-day1-shard-${{ github.sha }}-"
        "${{ needs.plan.outputs.normalized_seed }}-${{ matrix.workload }}-"
        "${{ matrix.freshness_id }}"
    ) in workflow
    assert (
        "pattern: r2-day1-shard-${{ github.sha }}-${{ needs.plan.outputs.normalized_seed }}-*"
    ) in workflow
    assert "name: r2-day1-${{ github.sha }}-${{ needs.plan.outputs.normalized_seed }}" in workflow


def test_workflow_matrix_uses_the_runner_exact_fraction_path_codec() -> None:
    workflow = (ROOT / ".github/workflows/day1-cost-model.yml").read_text(encoding="utf-8")

    assert "from scripts.run_day1_suite import freshness_path_id, rho_path_id" in workflow
    assert "'freshness_id': freshness_path_id(freshness)" in workflow
    assert "rho_ids = [rho_path_id(Fraction(str(value))) for value in rho_values]" in workflow
    assert "format(float(freshness)" not in workflow


def test_plan_job_runs_the_only_install_test_and_ruff_gate_before_matrix_output() -> None:
    workflow = (ROOT / ".github/workflows/day1-cost-model.yml").read_text(encoding="utf-8")

    install = ".venv/bin/python -m pip install -e '.[dev]'"
    pytest_gate = ".venv/bin/python -m pytest -q"
    ruff_gate = ".venv/bin/python -m ruff check ."
    assert workflow.count(install) == 1
    assert workflow.count(pytest_gate) == 1
    assert workflow.count(ruff_gate) == 1
    assert workflow.index(pytest_gate) < workflow.index("id: build-matrix")
    assert workflow.index(ruff_gate) < workflow.index("id: build-matrix")
    assert workflow.count("uses: actions/cache@v4") == 1
    assert workflow.count("uses: actions/cache/restore@v4") == 2
    assert workflow.count("fail-on-cache-miss: true") == 2


def test_day1_workflow_builds_a_dynamic_21_job_shard_matrix_and_aggregates_once() -> None:
    workflow = (ROOT / ".github/workflows/day1-cost-model.yml").read_text(encoding="utf-8")

    assert "plan:" in workflow
    assert "outputs:" in workflow
    assert "matrix: ${{ steps.build-matrix.outputs.matrix }}" in workflow
    assert "matrix: ${{ fromJSON(needs.plan.outputs.matrix) }}" in workflow
    assert "shard:" in workflow
    assert "needs: plan" in workflow
    assert "timeout-minutes: 330" in workflow
    assert "--workload '${{ matrix.workload }}'" in workflow
    assert "--freshness-seconds '${{ matrix.freshness_seconds }}'" in workflow
    assert "--queries-per-update" not in workflow
    assert (
        "name: r2-day1-shard-${{ github.sha }}-${{ needs.plan.outputs.normalized_seed }}-"
        "${{ matrix.workload }}-${{ matrix.freshness_id }}"
    ) in workflow

    assert "aggregate:" in workflow
    assert "needs: [plan, shard]" in workflow
    assert "uses: actions/download-artifact@v4" in workflow
    assert (
        "pattern: r2-day1-shard-${{ github.sha }}-${{ needs.plan.outputs.normalized_seed }}-*"
    ) in workflow
    assert "path: downloaded-shards" in workflow
    assert "merge-multiple: false" in workflow
    assert "downloaded-shards/<artifact-name>/SHARD_STATUS.json" in workflow
    assert "python scripts/aggregate_day1_shards.py" in workflow
    assert "--shards-dir downloaded-shards" in workflow
    assert workflow.count("SUITE_STATUS.json") == 1
    assert workflow.count("python scripts/run_day1_suite.py") == 1


def test_frozen_plan_supplies_the_exact_matrix_and_nine_rhos_per_shard() -> None:
    plan_payload = json.loads((ROOT / "config/experiment_plan.json").read_text(encoding="utf-8"))
    plan = load_experiment_plan(ROOT / "config/experiment_plan.json")

    cartesian = {
        (workload, freshness) for workload in plan.workloads for freshness in plan.freshness_seconds
    }
    assert plan_payload["plan_version"] == plan.plan_version == "0.2.0"
    assert plan_payload["synthetic"]["effective_slots"] == plan.effective_slots == 2048
    assert plan_payload["synthetic"]["partition_rows"] == plan.partition_rows == 128
    assert (
        plan_payload["synthetic"]["layout_measurement_kind"]
        == plan.layout_measurement_kind
        == "synthetic-proxy"
    )
    assert len(plan_payload["synthetic"]["workloads"]) == len(plan.workloads) == 7
    assert len(plan_payload["freshness_seconds"]) == len(plan.freshness_seconds) == 3
    assert len(plan_payload["synthetic"]["queries_per_update_grid"]) == len(plan.ratio_grid) == 9
    assert len(cartesian) == 21
