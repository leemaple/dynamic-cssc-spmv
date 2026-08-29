from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/route-a-qualification.yml"

CHECKOUT = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
SETUP = "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065"
UPLOAD = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
DOWNLOAD = "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
JOB_NAMES = (
    "qualification-simulator-producer",
    "qualification-simulator-independent-replay-and-guard",
    "qualification-native-case-shaped-producer",
    "qualification-native-independent-replay-and-guard",
    "qualification-combined-guard",
    "qualification-postrun-resource-admission",
)
ARTIFACT_NAMES = (
    "q1-simulator-pre-replay-handoff",
    "q2-simulator-guarded-receipt",
    "q3-native-pre-replay-build-plus-three-retained-packages",
    "q4-native-guarded-case-bundle",
    "q5-combined-guard-bundle",
    "q6-postrun-resource-admission-record",
)


def _workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_route_a_qualification_is_manual_one_shot_and_read_only() -> None:
    workflow = _workflow()
    assert re.search(r"(?m)^on:\n  workflow_dispatch:\n", workflow)
    assert "pull_request:" not in workflow
    assert "push:" not in workflow
    assert "schedule:" not in workflow
    assert "actions: read" in workflow
    assert "contents: read" in workflow
    assert "cancel-in-progress: false" in workflow
    assert "continue-on-error" not in workflow
    assert "rerun" not in workflow.lower()
    for field in (
        "expected_s1_git_sha",
        "expected_s2_git_sha",
        "expected_compatibility_receipt_sha256",
    ):
        assert workflow.count(f"      {field}:") == 1


def test_route_a_qualification_has_only_the_exact_serial_six_job_dag() -> None:
    workflow = _workflow()
    assert re.findall(r"(?m)^    name: (qualification-[^\n]+)$", workflow) == list(
        JOB_NAMES
    )
    assert re.findall(r"(?m)^    needs: (q[1-5])$", workflow) == [
        "q1",
        "q2",
        "q3",
        "q4",
        "q5",
    ]
    assert workflow.count("    timeout-minutes: 45") == 5
    assert workflow.count("    timeout-minutes: 5") == 1
    assert "if: always()" not in workflow


def test_every_job_executes_from_detached_s1_and_rechecks_s1_s2() -> None:
    workflow = _workflow()
    assert workflow.count(CHECKOUT) == 6
    assert workflow.count(SETUP) == 6
    assert workflow.count("ref: ${{ inputs.expected_s1_git_sha }}") == 6
    assert workflow.count("fetch-depth: 0") == 6
    assert workflow.count("persist-credentials: false") == 6
    assert workflow.count("scripts/verify_route_a_qualification_lineage.py") == 6
    assert workflow.count("test '${{ github.sha }}' = '${{ inputs.expected_s2_git_sha }}'") == 6
    assert workflow.count("python-version: '3.12.13'") == 6
    assert workflow.count("--require-hashes -r requirements-ci.txt") == 6
    assert workflow.count("--require-hashes -r requirements-publication.txt") == 6


def test_workflow_uploads_exactly_six_one_day_non_evidence_artifacts() -> None:
    workflow = _workflow()
    assert workflow.count(UPLOAD) == 6
    assert workflow.count("retention-days: 1") == 6
    assert workflow.count("if-no-files-found: error") == 6
    assert workflow.count("compression-level: 0") == 6
    for artifact in ARTIFACT_NAMES:
        assert workflow.count(f"name: {artifact}") >= 1
    assert workflow.count(DOWNLOAD) == 2


def test_q5_rehashes_provider_wrappers_and_q6_uses_only_live_api_state() -> None:
    workflow = _workflow()
    assert "scripts/run_route_a_combined_guard.py" in workflow
    assert "actions/artifacts/$Q2_ID/zip" in workflow
    assert "actions/artifacts/$Q4_ID/zip" in workflow
    assert "scripts/run_route_a_postrun_admission.py" in workflow
    assert "actions/runs/${{ github.run_id }}/jobs?per_page=100" in workflow
    assert "actions/runs/${{ github.run_id }}/artifacts?per_page=100" in workflow
    assert "--expected-run-attempt '${{ github.run_attempt }}'" in workflow
    assert "run_route_a_formal" not in workflow
    assert "control_route_a_publication.py" not in workflow
