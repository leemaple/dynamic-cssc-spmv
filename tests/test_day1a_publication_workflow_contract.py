from __future__ import annotations

import json
import re
import textwrap
from copy import deepcopy
from pathlib import Path

import pytest

from scripts.run_day1_suite import load_experiment_plan

ROOT = Path(__file__).parents[1]
PUBLICATION_WORKFLOW = ROOT / ".github/workflows/day1a-publication-cost-model.yml"
PUBLICATION_PLAN = ROOT / "config/experiment_plan_publication.json"
HISTORICAL_WORKFLOW = ROOT / ".github/workflows/day1-cost-model.yml"
HISTORICAL_PLAN = ROOT / "config/experiment_plan.json"
ROADMAP = ROOT / "docs/paper/publication-roadmap.md"


def _workflow(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _job_owning(workflow: str, command: str) -> str:
    job_starts = list(re.finditer(r"(?m)^  ([a-z][a-z0-9-]*):\n", workflow))
    owners: list[str] = []
    for index, match in enumerate(job_starts):
        end = job_starts[index + 1].start() if index + 1 < len(job_starts) else len(workflow)
        if command in workflow[match.start() : end]:
            owners.append(match.group(1))
    assert len(owners) == 1
    return owners[0]


def _job_block(workflow: str, job_name: str) -> str:
    start_match = re.search(rf"(?m)^  {re.escape(job_name)}:\n", workflow)
    assert start_match is not None
    next_match = re.search(r"(?m)^  [a-z][a-z0-9-]*:\n", workflow[start_match.end() :])
    end = (
        start_match.end() + next_match.start()
        if next_match is not None
        else len(workflow)
    )
    return workflow[start_match.start() : end]


def test_production_and_independent_replay_have_separate_timeout_budgets() -> None:
    workflow = _workflow(PUBLICATION_WORKFLOW)

    producer_job = _job_owning(workflow, "python scripts/run_day1_suite.py")
    replay_job = _job_owning(workflow, "python scripts/replay_day1_shard.py")
    producer = _job_block(workflow, producer_job)
    replay = _job_block(workflow, replay_job)
    pre_replay_name = (
        "r2-day1a-publication-pre-replay-${{ github.sha }}-"
        "${{ needs.plan.outputs.normalized_seed }}-${{ matrix.workload }}-"
        "${{ matrix.freshness_id }}"
    )

    assert producer_job != replay_job
    assert producer_job == "produce-shard"
    assert replay_job == "replay-shard"
    assert "timeout-minutes: 355" in producer
    assert "timeout-minutes: 355" in replay
    assert "needs: [plan, produce-shard]" in replay
    assert pre_replay_name in producer
    assert pre_replay_name in replay
    assert workflow.count(pre_replay_name) == 2
    assert "retention-days: 1" in producer
    assert replay.count("python scripts/replay_day1_shard.py") == 2
    assert replay.index("--verify-pre-replay-handoff-only") < replay.index("--source-sha")
    assert "Reject any non-exact pre-replay tree" in replay
    assert "if: ${{ inputs.diagnostic_single_shard == false }}" in replay
    assert "needs: [plan, replay-shard]" in _job_block(workflow, "aggregate")


def test_publication_workflow_is_manual_hosted_and_syntax_checked() -> None:
    workflow = _workflow(PUBLICATION_WORKFLOW)

    assert workflow.startswith("name: Day 1A publication-domain causal count evidence\n")
    assert "\n  workflow_dispatch:\n" in workflow
    assert "pull_request:" not in workflow
    assert "push:" not in workflow
    assert workflow.count("runs-on: ubuntu-latest") == 4
    assert "runs-on: self-hosted" not in workflow
    blocks = re.findall(
        r"(?ms)^ {10}.*?\.venv/bin/python - <<'PY'\n(.*?)^ {10}PY$",
        workflow,
    )
    assert len(blocks) == 4
    for index, block in enumerate(blocks):
        compile(textwrap.dedent(block), f"day1a-publication-guard-{index}.py", "exec")


def test_publication_workflow_pins_runtime_actions_cache_and_concurrency() -> None:
    workflow = _workflow(PUBLICATION_WORKFLOW)

    assert workflow.count("python-version: '3.12.13'") == 4
    assert workflow.count(
        "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
    ) == 4
    assert workflow.count(
        "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065"
    ) == 4
    assert workflow.count(
        "actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830"
    ) == 1
    assert workflow.count(
        "actions/cache/restore@0057852bfaa89a56745cba8c7296529d2fc39830"
    ) == 3
    assert workflow.count(
        "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
    ) == 2
    assert workflow.count(
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
    ) == 3
    assert re.search(r"uses:\s+actions/[^\s]+@v[0-9]", workflow) is None
    assert "group: day1a-publication-${{ github.repository_id }}-${{ github.sha }}" in workflow
    assert "cancel-in-progress: false" in workflow
    assert workflow.count("day1a-publication-python-${{ runner.os }}-py31213-") == 4
    assert "key: day1-python-" not in workflow


def test_publication_workflow_binds_every_stage_to_the_formal_plan() -> None:
    workflow = _workflow(PUBLICATION_WORKFLOW)
    plan_path = "config/experiment_plan_publication.json"

    assert workflow.count(plan_path) == 5
    assert f"plan = load_experiment_plan('{plan_path}')" in workflow
    assert workflow.count(f"--experiment-plan {plan_path}") == 4
    assert "config/experiment_plan.json" not in workflow
    assert workflow.count("assert p['experiment_plan_version'] == '0.3.0'") == 2
    assert workflow.count("assert p['effective_slots'] == 4096") == 2
    assert workflow.count("assert p['partition_rows'] == 4096") == 2


def test_publication_workflow_freezes_the_complete_21_by_9_grid() -> None:
    payload = json.loads(PUBLICATION_PLAN.read_text(encoding="utf-8"))
    plan = load_experiment_plan(PUBLICATION_PLAN)
    cartesian = {
        (workload, freshness)
        for workload in plan.workloads
        for freshness in plan.freshness_seconds
    }

    assert payload["plan_version"] == plan.plan_version == "0.3.0"
    assert payload["synthetic"]["rows"] == plan.rows == 4096
    assert payload["synthetic"]["cols"] == plan.cols == 8193
    assert payload["synthetic"]["effective_slots"] == plan.effective_slots == 4096
    assert payload["synthetic"]["partition_rows"] == plan.partition_rows == 4096
    assert len(plan.workloads) == 7
    assert len(plan.freshness_seconds) == 3
    assert len(plan.ratio_grid) == 9
    assert len(cartesian) == 21

    workflow = _workflow(PUBLICATION_WORKFLOW)
    assert "max-parallel: 21" in workflow
    assert "assert len(include) == 21" in workflow
    assert "assert p['cells_expected'] == p['cells_completed'] == 9" in workflow
    assert "assert p['cells_expected'] == p['cells_completed'] == 189" in workflow


def test_publication_workflow_has_one_non_admissible_hosted_smoke() -> None:
    workflow = _workflow(PUBLICATION_WORKFLOW)

    assert "diagnostic_single_shard:" in workflow
    assert "Run one non-admissible hosted performance smoke without uploading evidence" in workflow
    assert "if item['workload'] == 'mixed-insert-delete-modify'" in workflow
    assert "and item['freshness_seconds'] == '1'" in workflow
    assert "'[NON-ADMISSIBLE SMOKE] '" in workflow
    assert workflow.count("if: ${{ inputs.diagnostic_single_shard == false }}") == 2
    assert "github.event.inputs.diagnostic_single_shard" not in workflow


@pytest.mark.parametrize(
    ("diagnostic", "expected_count"),
    [("false", 21), ("true", 1)],
)
def test_publication_matrix_executes_in_full_or_single_shard_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    diagnostic: str,
    expected_count: int,
) -> None:
    workflow = _workflow(PUBLICATION_WORKFLOW)
    blocks = re.findall(
        r"(?ms)^ {10}.*?\.venv/bin/python - <<'PY'\n(.*?)^ {10}PY$",
        workflow,
    )
    output = tmp_path / f"matrix-{diagnostic}.txt"
    monkeypatch.setenv("DIAGNOSTIC_SINGLE_SHARD", diagnostic)
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))

    exec(compile(textwrap.dedent(blocks[1]), "day1a-publication-matrix.py", "exec"))

    matrix = json.loads(output.read_text(encoding="utf-8").removeprefix("matrix=").strip())
    assert len(matrix["include"]) == expected_count
    if diagnostic == "true":
        assert matrix["include"] == [
            {
                "workload": "mixed-insert-delete-modify",
                "freshness_seconds": "1",
                "freshness_id": "freshness-n1d1s",
            }
        ]


def test_publication_plan_differs_from_the_historical_plan_only_in_domain_identity() -> None:
    historical = json.loads(HISTORICAL_PLAN.read_text(encoding="utf-8"))
    publication = json.loads(PUBLICATION_PLAN.read_text(encoding="utf-8"))
    normalized = deepcopy(publication)

    normalized["plan_version"] = historical["plan_version"]
    for field in ("rows", "cols", "effective_slots", "partition_rows"):
        normalized["synthetic"][field] = historical["synthetic"][field]

    assert normalized == historical


def test_publication_workflow_authorizes_only_day1a_counts_and_day2_key_planning() -> None:
    workflow = _workflow(PUBLICATION_WORKFLOW)

    for guard in (
        "assert rotation_inventory['rows'] == 4096",
        "assert rotation_inventory['cols'] == 8193",
        "assert rotation_inventory['effective_slots'] == 4096",
        "assert rotation_inventory['partition_rows'] == 4096",
        "assert rotation_inventory['publication_rows'] == 4096",
        "assert rotation_inventory['publication_cols'] == 8193",
        "assert rotation_inventory['publication_effective_slots'] == 4096",
        "assert rotation_inventory['publication_partition_rows'] == 4096",
        "assert rotation_inventory['publication_domain_match'] is True",
        "assert rotation_inventory['day2_direct_key_plan_eligible'] is True",
        "assert day1a_receipt['day1a_count_evidence_authorized'] is True",
        "assert day1a_receipt['day2_direct_key_plan_authorized'] is True",
        "assert day1a_receipt['complete_cost_claim_allowed'] is False",
        "assert day1a_receipt['formal_performance_claim_allowed'] is False",
        "assert day1a_receipt['paper_verdict_allowed'] is False",
        "assert day1a_receipt['security_claim_allowed'] is False",
    ):
        assert guard in workflow
    assert workflow.count("assert p['complete_cost_claim_allowed'] is False") == 2
    assert workflow.count("assert p['security_claim_allowed'] is False") == 2
    assert workflow.count("assert p['formal_performance_claim'] is False") == 2


def test_publication_artifacts_cannot_collide_with_historical_day1_artifacts() -> None:
    workflow = _workflow(PUBLICATION_WORKFLOW)

    shard_prefix = "r2-day1a-publication-shard-${{ github.sha }}-"
    aggregate_prefix = "r2-day1a-publication-${{ github.sha }}-"
    assert f"name: {shard_prefix}" in workflow
    assert f"pattern: {shard_prefix}" in workflow
    assert f"name: {aggregate_prefix}" in workflow
    assert "--stage R2-Day1A-publication-domain" in workflow
    assert "name: r2-day1-shard-" not in workflow
    assert "name: r2-day1-${{ github.sha }}-" not in workflow


def test_historical_day1_contract_remains_exploratory_and_unauthorized_for_day2() -> None:
    payload = json.loads(HISTORICAL_PLAN.read_text(encoding="utf-8"))
    plan = load_experiment_plan(HISTORICAL_PLAN)
    workflow = _workflow(HISTORICAL_WORKFLOW)

    assert payload["plan_version"] == plan.plan_version == "0.2.0"
    assert payload["synthetic"]["rows"] == plan.rows == 512
    assert payload["synthetic"]["cols"] == plan.cols == 512
    assert payload["synthetic"]["effective_slots"] == plan.effective_slots == 2048
    assert payload["synthetic"]["partition_rows"] == plan.partition_rows == 128
    assert workflow.count("assert p['experiment_plan_version'] == '0.2.0'") == 2
    assert "assert rotation_inventory['publication_domain_match'] is False" in workflow
    assert "assert rotation_inventory['day2_direct_key_plan_eligible'] is False" in workflow
    assert "assert day1a_receipt['day2_direct_key_plan_authorized'] is False" in workflow


def test_roadmap_names_the_formal_plan_as_the_only_day2_authorized_domain() -> None:
    roadmap = ROADMAP.read_text(encoding="utf-8")

    for required in (
        "config/experiment_plan.json",
        "config/experiment_plan_publication.json",
        ".github/workflows/day1a-publication-cost-model.yml",
        "day2_direct_key_plan_authorized=false",
        "day2_direct_key_plan_authorized=true",
        "the sole route eligible",
    ):
        assert required in roadmap
    assert "A later preregistered Day1A plan must" not in roadmap


def test_publication_contract_is_in_its_own_ci_gate() -> None:
    workflow = _workflow(PUBLICATION_WORKFLOW)

    assert workflow.count("tests/test_day1a_publication_workflow_contract.py \\") == 2
    assert workflow.count("tests/test_day1_causal_runner.py \\") == 2
    assert workflow.count(".venv/bin/python -m pytest -q") == 1
    assert workflow.count(".venv/bin/python -m ruff check \\") == 1
