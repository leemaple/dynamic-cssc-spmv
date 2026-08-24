from __future__ import annotations

import re
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github/workflows/day2-publication-calibration.yml"


def _workflow() -> str:
    return WORKFLOW_PATH.read_text(encoding="utf-8")


def test_formal_day2_workflow_is_manual_zero_input_and_hosted() -> None:
    workflow = _workflow()

    assert workflow.startswith("name: Day 2 formal publication calibration\n")
    assert re.search(r"(?m)^on:\n  workflow_dispatch:\n\npermissions:$", workflow)
    assert "inputs:" not in workflow
    assert "${{ inputs." not in workflow
    assert "pull_request:" not in workflow
    assert "push:" not in workflow
    assert workflow.count("runs-on: ubuntu-24.04") == 1
    assert "self-hosted" not in workflow
    assert "actions: read" in workflow
    assert "contents: read" in workflow


def test_formal_day2_workflow_pins_every_third_party_action() -> None:
    workflow = _workflow()

    assert workflow.count(
        "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
    ) == 1
    assert workflow.count(
        "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065"
    ) == 1
    assert workflow.count(
        "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
    ) == 1
    assert workflow.count(
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
    ) == 2
    assert re.search(r"uses:\s+actions/[^\s]+@v[0-9]", workflow) is None
    assert "actions/cache" not in workflow
    assert "fetch-depth: 0" in workflow
    assert "persist-credentials: false" in workflow
    assert "python-version: '3.12.13'" in workflow


def test_formal_day2_download_uses_only_reviewed_provider_ids() -> None:
    workflow = _workflow()

    assert "validate_day2_calibration_profile_anchor_document(content)" in workflow
    assert "assert len(document['anchors']) == 1" in workflow
    assert "run_id={anchor['day1a_workflow_run_id']}" in workflow
    assert "artifact_id={anchor['day1a_artifact_id']}" in workflow
    assert "artifact-ids: ${{ steps.day1a-provider.outputs.artifact_id }}" in workflow
    assert "run-id: ${{ steps.day1a-provider.outputs.run_id }}" in workflow
    assert "github-token: ${{ secrets.GITHUB_TOKEN }}" in workflow
    assert "pattern:" not in workflow
    assert "merge-multiple:" not in workflow
    assert "capture_day2_github_metadata.py day1a-input" in workflow


def test_formal_day2_producer_accepts_paths_not_semantic_overrides() -> None:
    workflow = _workflow()
    step_start = workflow.index("Run the one-use detached formal producer")
    producer_start = workflow.index("scripts/run_day2_calibration_isolated.py", step_start)
    producer_end = workflow.index("\n\n      - name:", producer_start)
    producer = workflow[producer_start:producer_end]

    for required in (
        "--day1a-directory",
        "--github-artifact-metadata",
        "--output-archive",
        "${RUNNER_TEMP}/day2-output/day2-calibration.zip",
    ):
        assert required in producer
    for forbidden in (
        "--seed",
        "--rotation",
        "--profile",
        "--source-sha",
        "--authority",
        "--warmup",
        "--repetitions",
    ):
        assert forbidden not in producer
    assert "if: always()" not in workflow


def test_formal_day2_keeps_outputs_outside_the_source_checkout() -> None:
    workflow = _workflow()

    assert "path: ${{ runner.temp }}/day1a-artifact" in workflow
    assert workflow.count("${RUNNER_TEMP}/day1a-artifact") >= 2
    assert workflow.count("${RUNNER_TEMP}/day2-output") >= 3
    assert "--output-archive results/" not in workflow
    assert "path: results/" not in workflow
    assert "path: artifacts/" not in workflow


def test_formal_day2_preserves_wrapper_and_inner_archive_identities() -> None:
    workflow = _workflow()

    evidence_name = (
        "r3-day2-calibration-${{ github.sha }}-${{ github.run_id }}-"
        "${{ github.run_attempt }}"
    )
    metadata_name = (
        "r3-day2-calibration-metadata-${{ github.sha }}-${{ github.run_id }}-"
        "${{ github.run_attempt }}"
    )
    assert f"name: {evidence_name}" in workflow
    assert f"name: {metadata_name}" in workflow
    assert "DAY2_UPLOADED_ARTIFACT_ID:" in workflow
    assert "DAY2_UPLOADED_ARTIFACT_DIGEST:" in workflow
    assert "capture_day2_github_metadata.py day2-output" in workflow
    assert workflow.count("compression-level: 0") == 2
    assert workflow.count("if-no-files-found: error") == 2
    assert workflow.count("overwrite: false") == 2


def test_formal_day2_inline_guard_is_valid_python() -> None:
    workflow = _workflow()
    blocks = re.findall(
        r"(?ms)^ {10}\.venv/bin/python - <<'PY'\n(.*?)^ {10}PY$",
        workflow,
    )

    assert len(blocks) == 1
    compile(textwrap.dedent(blocks[0]), "day2-provider-anchor-guard.py", "exec")


def test_formal_day2_contract_tests_itself_before_measurement() -> None:
    workflow = _workflow()
    gate = workflow.index("Validate the exact formal producer surface")
    measurement = workflow.index("Run the one-use detached formal producer")

    assert gate < measurement
    assert "tests/test_day2_publication_workflow_contract.py" in workflow[gate:measurement]
