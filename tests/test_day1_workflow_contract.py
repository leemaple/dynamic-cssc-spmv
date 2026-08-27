from __future__ import annotations

import json
import re
import textwrap
from pathlib import Path

from scripts.run_day1_suite import load_experiment_plan

ROOT = Path(__file__).parents[1]


def test_every_embedded_day1_python_guard_is_syntax_valid() -> None:
    workflow = (ROOT / ".github/workflows/day1-cost-model.yml").read_text(encoding="utf-8")
    blocks = re.findall(
        r"(?ms)^ {10}.*?\.venv/bin/python - <<'PY'\n(.*?)^ {10}PY$",
        workflow,
    )

    assert len(blocks) == 4
    for index, block in enumerate(blocks):
        compile(textwrap.dedent(block), f"day1-workflow-guard-{index}.py", "exec")


def test_ci_lock_exactly_pins_and_hashes_every_dependency() -> None:
    lock_path = ROOT / "requirements-ci.txt"
    assert lock_path.is_file()

    lock = lock_path.read_text(encoding="utf-8")
    requirements = [line for line in lock.splitlines() if line and not line.startswith((" ", "#"))]
    assert requirements
    assert all("==" in requirement for requirement in requirements)
    assert all(
        "--hash=sha256:" in block for block in re.split(r"(?m)(?=^[^ #])", lock) if "==" in block
    )
    assert re.search(r"(?m)^matplotlib==\d+\.\d+\.\d+", lock)


def test_day1_workflow_installs_only_the_hashed_ci_lock() -> None:
    workflow = (ROOT / ".github/workflows/day1-cost-model.yml").read_text(encoding="utf-8")

    install = ".venv/bin/python -m pip install --require-hashes -r requirements-ci.txt"
    assert workflow.count(install) == 1
    assert "pip install -e" not in workflow
    assert ".[dev]" not in workflow
    assert workflow.count("hashFiles('requirements-ci.txt')") == 3
    assert "uv.lock" not in workflow
    assert "\nenv:\n  PYTHONPATH: src:.\n\njobs:" in workflow


def test_every_day1_job_checks_out_complete_history_without_credentials() -> None:
    workflow = (ROOT / ".github/workflows/day1-cost-model.yml").read_text(encoding="utf-8")

    assert workflow.count("uses: actions/checkout@v4") == 3
    assert workflow.count("fetch-depth: 0") == 3
    assert workflow.count("persist-credentials: false") == 3


def test_day1_workflow_guards_the_causal_evidence_contract() -> None:
    workflow = (ROOT / ".github/workflows/day1-cost-model.yml").read_text(encoding="utf-8")

    assert "p['status']" not in workflow
    assert "inputs.updates" not in workflow
    assert workflow.count("assert p['schema'] == 'day1-causal-predicted-v2'") == 2
    assert "assert p['state_model'] == 'persistent-strategy-snapshots'" in workflow
    assert "assert p['measurement_kind'] == 'predicted-proxy'" in workflow
    assert "assert p['gate_eligible'] is False" in workflow
    assert "assert p['complete_cost_claim_allowed'] is False" in workflow
    assert "assert p['security_claim_allowed'] is False" in workflow
    assert "assert p['formal_performance_claim'] is False" in workflow
    assert "assert p['complete_reference_set'] is True" in workflow
    assert "assert p['suite_complete'] is True" in workflow
    assert workflow.count("assert p['experiment_plan_version'] == '0.2.0'") == 2
    assert workflow.count("assert p['effective_slots'] == 2048") == 2
    assert workflow.count("assert p['partition_rows'] == 128") == 2
    assert workflow.count("assert p['layout_measurement_kind'] == 'synthetic-proxy'") == 2
    assert (
        "assert p['deferred_unpriced_plan_dimensions'] == ['bandwidth_profiles_mbps']" in workflow
    )
    assert "assert p['preflight']['status'] == 'pass'" in workflow


def test_day1_workflow_guards_the_exact_role_aware_candidate_roster() -> None:
    workflow = (ROOT / ".github/workflows/day1-cost-model.yml").read_text(encoding="utf-8")

    assert workflow.count("assert p['fixed_candidate_count'] == 14") == 2
    assert workflow.count("assert p['reference_candidate_count'] == 13") == 2
    assert workflow.count("assert p['ablation_candidate_count'] == 1") == 2
    assert workflow.count("assert p['candidate_ids'] == fixed_candidate_ids") == 2
    assert workflow.count("assert p['reference_candidate_ids'] == reference_candidate_ids") == 2
    assert workflow.count("assert p['ablation_candidate_ids'] == ablation_candidate_ids") == 2
    assert (
        workflow.count(
            "assert ablation_candidate_ids == ['packed-coo-client-lane-delta/capacity=128']"
        )
        == 2
    )
    assert (
        workflow.count("assert set(reference_candidate_ids).isdisjoint(ablation_candidate_ids)")
        == 2
    )
    assert workflow.count("assert p['deferred_reference_baselines'] == []") == 2


def test_aggregate_guard_revalidates_all_189_role_and_rotation_proofs() -> None:
    workflow = (ROOT / ".github/workflows/day1-cost-model.yml").read_text(encoding="utf-8")

    assert "from dynamic_cssc.report import validate_causal_payload" in workflow
    assert "metrics_paths = sorted(Path('results/day1').glob('*/*/*/metrics.json'))" in workflow
    assert "assert len(metrics_paths) == 189" in workflow
    assert "validate_causal_payload(payload)" in workflow
    assert "assert len(payload['records']) == 16" in workflow
    assert "assert proof['fixed_candidate_count'] == 14" in workflow
    assert "assert proof['reference_candidate_count'] == 13" in workflow
    assert "assert proof['ablation_candidate_count'] == 1" in workflow
    assert "assert proof['tuning_candidate_count'] == 13" in workflow
    assert "assert proof['record_count'] == 16" in workflow
    assert "assert set(measured).issubset(required)" in workflow


def test_dispatch_seed_is_normalized_once_from_env_before_any_use() -> None:
    workflow = (ROOT / ".github/workflows/day1-cost-model.yml").read_text(encoding="utf-8")

    assert workflow.count("${{ inputs.seed }}") == 1
    assert "RAW_SEED: ${{ inputs.seed }}" in workflow
    assert "parse_canonical_seed(os.environ['RAW_SEED'])" in workflow
    assert "normalized_seed: ${{ steps.normalize-seed.outputs.normalized_seed }}" in workflow
    assert workflow.count("DAY1_SEED: ${{ needs.plan.outputs.normalized_seed }}") == 3
    assert workflow.count('--seed "$DAY1_SEED"') == 3
    assert "--seed '${{ needs.plan.outputs.normalized_seed }}'" not in workflow
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

    install = ".venv/bin/python -m pip install --require-hashes -r requirements-ci.txt"
    pytest_gate = ".venv/bin/python -m pytest -q"
    ruff_gate = ".venv/bin/python -m ruff check \\\n"
    assert workflow.count(install) == 1
    assert workflow.count(pytest_gate) == 1
    assert workflow.count(ruff_gate) == 1
    for behavior_path in (
        "scripts/produce_day1_registration_evidence.py",
        "src/dynamic_cssc/day1a_export.py",
        "src/dynamic_cssc/day1_registration_evidence.py",
        "src/dynamic_cssc/plaintext_oracle.py",
        "tests/test_day1_registration_evidence.py",
    ):
        assert f"{behavior_path} \\" in workflow
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
    assert "max-parallel: 21" in workflow
    assert "timeout-minutes: 355" in workflow
    assert "DAY1_WORKLOAD: ${{ matrix.workload }}" in workflow
    assert "DAY1_FRESHNESS_SECONDS: ${{ matrix.freshness_seconds }}" in workflow
    assert workflow.count('--workload "$DAY1_WORKLOAD"') == 2
    assert workflow.count('--freshness-seconds "$DAY1_FRESHNESS_SECONDS"') == 2
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
    assert workflow.count("DAY1A_COUNT_BUNDLE.json") == 1
    assert workflow.count("DAY1A_ROTATION_INVENTORY.json") == 1
    assert workflow.count("DAY1A_AUTHORITY_RECEIPT.json") == 1
    assert workflow.count("python scripts/run_day1_suite.py") == 1


def test_each_shard_replays_serialized_evidence_in_a_second_process_before_upload() -> None:
    workflow = (ROOT / ".github/workflows/day1-cost-model.yml").read_text(encoding="utf-8")

    generation = workflow.index("python scripts/run_day1_suite.py")
    replay = workflow.index("python scripts/replay_day1_shard.py")
    receipt_guard = workflow.index("results/day1-shard/REPLAY_RECEIPT.json")
    upload = workflow.index("uses: actions/upload-artifact@v4", replay)

    assert generation < replay < receipt_guard < upload
    assert workflow.count("python scripts/replay_day1_shard.py") == 1
    assert workflow.count("\n          SOURCE_GIT_SHA: ${{ github.sha }}") == 2
    assert workflow.count('--source-sha "$SOURCE_GIT_SHA"') == 2
    assert "--source-sha '${{ github.sha }}'" not in workflow
    assert "if: always()" not in workflow


def test_shard_guard_requires_a_complete_digest_bound_replay_receipt() -> None:
    workflow = (ROOT / ".github/workflows/day1-cost-model.yml").read_text(encoding="utf-8")

    assert "assert r['schema'] == 'day1-shard-replay-receipt-v1'" in workflow
    assert (
        "assert r['validator_schema'] == 'day1-separate-deterministic-replay-validator-v3'"
    ) in workflow
    assert "assert r['validator_version'] == '3'" in workflow
    assert "assert r['source_git_sha'] == os.environ['EXPECTED_SOURCE_GIT_SHA']" in workflow
    assert "assert r['experiment_plan_sha256'] == p['experiment_plan_sha256']" in workflow
    assert "assert r['manifest_sha256'] == p['manifest_sha256']" in workflow
    assert "assert r['seed'] == p['seed'] == int(os.environ['EXPECTED_SHARD_SEED'])" in workflow
    assert "assert r['workload'] == p['workload'] == os.environ['EXPECTED_WORKLOAD']" in workflow
    assert "assert r['freshness_seconds_fraction'] == p['freshness_seconds_fraction']" in workflow
    assert "assert r['rho_ids'] == p['rho_ids']" in workflow
    assert "assert r['cells_expected'] == r['cells_replayed'] == 9" in workflow
    assert "assert len(r['cells']) == len({c['rho_id'] for c in r['cells']}) == 9" in workflow
    assert "assert r['verified'] is True" in workflow
    assert "assert '  REPLAY_RECEIPT.json' in checksums" in workflow
    assert "(cd results/day1-shard && sha256sum --check --strict SHA256SUMS)" in workflow


def test_aggregate_guard_binds_all_receipts_to_source_and_verifies_final_checksums() -> None:
    workflow = (ROOT / ".github/workflows/day1-cost-model.yml").read_text(encoding="utf-8")

    aggregate = workflow.index("python scripts/aggregate_day1_shards.py")
    final_checksum_check = workflow.index(
        "(cd results/day1 && sha256sum --check --strict SHA256SUMS)"
    )
    package = workflow.index("python scripts/package_review_bundle.py")

    assert aggregate < final_checksum_check < package
    assert workflow.count("\n          EXPECTED_SOURCE_GIT_SHA: ${{ github.sha }}") == 2
    assert "assert p['source_git_sha'] == os.environ['EXPECTED_SOURCE_GIT_SHA']" in workflow
    receipt_count_guard = (
        "assert p['replay_receipts_expected'] == p['replay_receipts_completed'] == 21"
    )
    assert receipt_count_guard in workflow
    assert "assert p['replay_receipt_schema'] == 'day1-shard-replay-receipt-v1'" in workflow
    validator_schema_guard = (
        "assert p['replay_validator_schema'] == 'day1-separate-deterministic-replay-validator-v3'"
    )
    assert validator_schema_guard in workflow
    assert "assert len(p['replay_receipts']) == 21" in workflow
    assert "assert set(item) == receipt_item_keys" in workflow
    assert "assert re.fullmatch(r'[0-9a-f]{64}', item['sha256'])" in workflow
    assert "assert count_bundle['fixed_record_count'] == 189 * 14" in workflow
    assert "assert rotation_inventory['publication_domain_match'] is False" in workflow
    assert "assert day1a_receipt['day1a_count_evidence_authorized'] is True" in workflow
    assert "assert day1a_receipt['day2_direct_key_plan_authorized'] is False" in workflow


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
