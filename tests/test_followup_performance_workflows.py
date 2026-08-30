from __future__ import annotations

import re
from pathlib import Path

from dynamic_cssc.followup_performance_formal_matrix import (
    followup_formal_unit_specs,
)
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
QUALIFICATION = WORKFLOWS / "followup-performance-qualification.yml"
FORMAL = WORKFLOWS / "followup-performance-formal.yml"
ANALYSIS = WORKFLOWS / "followup-performance-analysis.yml"
FORMAL_ACTION = ROOT / ".github/actions/followup-formal-unit/action.yml"
AUTHORITY_ACTION = ROOT / ".github/actions/followup-provider-authority/action.yml"
CONTROL_WORKFLOWS = (
    WORKFLOWS / "followup-performance-ci.yml",
    WORKFLOWS / "followup-performance-pre-s1.yml",
    WORKFLOWS / "followup-performance-registration.yml",
    WORKFLOWS / "followup-performance-source-anchor.yml",
    WORKFLOWS / "followup-performance-independent-review.yml",
)
CHECKOUT = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
SETUP = "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065"
UPLOAD = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
DOWNLOAD = "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
REGISTERED_VALUES = ("20260901", "20260902", "20260903", "20260904", "2026090202")
SENTINEL_PROFILE = RouteAScientificProfile(
    profile_id="workflow-contract-sentinel",
    qualification_seed=94_001,
    formal_seeds=(94_002, 94_003, 94_004),
    query_vector_seed=9_400_102,
    machine_plan_sha256="0" * 64,
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_followup_qualification_is_manual_read_only_and_exactly_once() -> None:
    workflow = _text(QUALIFICATION)
    assert re.search(r"(?m)^on:\n  workflow_dispatch:\n", workflow)
    assert "push:" not in workflow
    assert "pull_request:" not in workflow
    assert "schedule:" not in workflow
    assert "actions: read" in workflow
    assert "contents: read" in workflow
    assert workflow.count("contents: write") == 1
    assert "expected_authority_claim_oid" in workflow
    assert "cancel-in-progress: false" in workflow
    assert "rerun" not in workflow.lower()
    assert "continue-on-error" not in workflow
    assert all(value not in workflow for value in REGISTERED_VALUES)


def test_followup_qualification_preserves_the_frozen_six_job_resource_dag() -> None:
    workflow = _text(QUALIFICATION)
    assert re.findall(r"(?m)^    name: (qualification-[^\n]+)$", workflow) == [
        "qualification-simulator-producer",
        "qualification-simulator-independent-replay-and-guard",
        "qualification-native-case-shaped-producer",
        "qualification-native-independent-replay-and-guard",
        "qualification-combined-guard",
        "qualification-postrun-resource-admission",
    ]
    assert workflow.count("    timeout-minutes: 45") == 5
    assert workflow.count("    timeout-minutes: 5") == 1
    assert "    needs: q1" in workflow
    assert "    needs: q2" in workflow
    assert "    needs: q3" in workflow
    assert "    needs: [q2, q4]" in workflow
    assert "    needs: q5" in workflow
    assert "if: always()" not in workflow


def test_every_qualification_job_reuses_the_same_exact_s1_s2_checks() -> None:
    workflow = _text(QUALIFICATION)
    for anchor in (
        "validate-identities",
        "checkout-s1",
        "verify-dispatch",
        "setup-python",
        "install-python",
        "verify-lineage",
    ):
        assert workflow.count(f"&{anchor}") == 1
        expected_aliases = 4 if anchor == "install-python" else 5
        assert workflow.count(f"*{anchor}") == expected_aliases
    assert CHECKOUT in workflow
    assert SETUP in workflow
    assert "scripts/verify_followup_performance_lineage.py" in workflow
    assert "ref: ${{ inputs.expected_s1_git_sha }}" in workflow


def test_qualification_uses_only_new_outer_artifacts_and_followup_clis() -> None:
    workflow = _text(QUALIFICATION)
    assert workflow.count(UPLOAD) == 6
    assert workflow.count(DOWNLOAD) == 2
    assert workflow.count("retention-days: 1") == 6
    assert workflow.count("compression-level: 0") == 6
    assert workflow.count("if-no-files-found: error") == 6
    for stage in range(1, 7):
        assert f"^followup-performance-v1-qualification-q{stage}-" in workflow
    for script in (
        "run_followup_performance_qualification.py",
        "run_followup_performance_native_qualification.py",
        "run_followup_performance_combined_guard.py",
        "run_followup_performance_postrun_admission.py",
    ):
        assert script in workflow
    assert "scripts/run_route_a_" not in workflow


def test_control_workflows_are_manual_pinned_and_emit_only_outer_receipts() -> None:
    for path in CONTROL_WORKFLOWS:
        workflow = _text(path)
        assert re.search(r"(?m)^on:\n  workflow_dispatch:\n", workflow)
        assert "push:" not in workflow
        assert "pull_request:" not in workflow
        assert CHECKOUT in workflow
        assert SETUP in workflow
        assert UPLOAD in workflow
        assert "cancel-in-progress: false" in workflow
        assert all(value not in workflow for value in REGISTERED_VALUES)
        assert "followup-performance-v1-" in workflow


def test_registration_and_anchor_controls_execute_only_after_exact_s2_exists() -> None:
    registration = _text(WORKFLOWS / "followup-performance-registration.yml")
    source_anchor = _text(WORKFLOWS / "followup-performance-source-anchor.yml")
    for workflow in (registration, source_anchor):
        assert "ref: ${{ inputs.expected_s2_git_sha }}" in workflow
        assert 'test "$(git rev-parse HEAD)" = "$EXPECTED_S2"' in workflow or (
            'test "$(git rev-parse HEAD)" = "$S2"' in workflow
        )
        assert "scripts/verify_followup_performance_lineage.py" in workflow
    assert "scripts/produce_followup_performance_registration.py" in registration
    assert "scripts/verify_followup_performance_registration.py" in registration
    assert "--kind source-anchor" in source_anchor


def test_formal_campaign_is_manual_one_shot_and_contains_no_registered_seed_literal() -> None:
    workflow = _text(FORMAL)
    action = _text(FORMAL_ACTION)
    assert re.search(r"(?m)^on:\n  workflow_dispatch:\n", workflow)
    assert "push:" not in workflow
    assert "pull_request:" not in workflow
    assert "schedule:" not in workflow
    assert "cancel-in-progress: false" in workflow
    assert "continue-on-error" not in workflow
    assert all(value not in workflow + action for value in REGISTERED_VALUES)
    assert "expected_qualification_run_id" in workflow
    assert "followup-performance-qualification.yml" in workflow
    assert "    name: formal-launch-admission" in workflow
    assert "formal-launch-binding" not in workflow
    assert workflow.count("contents: write") == 1
    assert "expected_authority_claim_oid" in workflow


def test_provider_authority_uses_one_exact_compare_and_swap_before_science() -> None:
    qualification = _text(QUALIFICATION)
    formal = _text(FORMAL)
    action = _text(AUTHORITY_ACTION)
    for token in (
        "beforeOid:$before",
        "afterOid:$after",
        "force:false",
        "test \"$GITHUB_RUN_ATTEMPT\" = 1",
        "dynamic-cssc-followup-performance-qualification-authority-v1",
        "dynamic-cssc-followup-performance-formal-authority-v1",
        "dynamic-cssc-followup-performance-2026-08-30",
    ):
        assert token in action
    assert qualification.index("Bind this sole provider run") < qualification.index(
        "Run q1 simulator producer"
    )
    assert formal.index("Bind this sole formal provider run") < formal.index(
        "formal-00-acquisition-producer"
    )


def test_formal_campaign_has_exact_strictly_serial_thirty_four_unit_jobs() -> None:
    workflow = _text(FORMAL)
    specs = followup_formal_unit_specs(SENTINEL_PROFILE)
    expected_names = [
        name
        for spec in specs
        for name in (spec.producer_job_name, spec.guard_job_name)
    ]
    assert re.findall(
        r"(?m)^    name: (formal-[0-9]{2}[^\n]+(?:producer|independent-replay-and-guard))$",
        workflow,
    ) == expected_names
    for spec in specs:
        producer = f"u{spec.ordinal:02d}_producer"
        guard = f"u{spec.ordinal:02d}_guard"
        predecessor = "launch" if spec.ordinal == 0 else f"u{spec.ordinal - 1:02d}_guard"
        producer_needs = (
            f"[{predecessor}, u00_guard]"
            if spec.unit_kind == "formal-ordered-event"
            else predecessor
        )
        guard_needs = (
            f"[{producer}, u00_guard]"
            if spec.unit_kind == "formal-ordered-event"
            else producer
        )
        producer_match = re.search(
            rf"(?ms)^  {producer}:\n(.*?)(?=^  \S|\Z)",
            workflow,
        )
        guard_match = re.search(
            rf"(?ms)^  {guard}:\n(.*?)(?=^  \S|\Z)",
            workflow,
        )
        assert producer_match is not None
        assert guard_match is not None
        producer_block = producer_match.group(1)
        guard_block = guard_match.group(1)
        assert f"    needs: {producer_needs}" in producer_block
        assert f"    needs: {guard_needs}" in guard_block
        assert producer_block.count(f"    timeout-minutes: {spec.reservation_minutes}") == 1
        assert guard_block.count(f"    timeout-minutes: {spec.reservation_minutes}") == 1


def test_formal_units_share_one_pinned_exact_s1_action_and_terminal_closure() -> None:
    workflow = _text(FORMAL)
    action = _text(FORMAL_ACTION)
    assert workflow.count(CHECKOUT) == 37
    assert action.count(SETUP) == 1
    assert action.count(UPLOAD) == 1
    assert action.count(DOWNLOAD) == 2
    assert "scripts/run_followup_performance_formal_unit.py" in action
    assert "scripts/verify_followup_performance_lineage.py" in action
    assert "phase: private-handoff" in workflow
    assert "phase: guarded-final" in workflow
    assert workflow.count("retention-days: '1'") == 17
    assert workflow.count("retention-days: '90'") == 17
    assert "name: formal-terminal-admission" in workflow
    assert "scripts/run_followup_performance_terminal_admission.py" in workflow
    assert "name: formal-aggregate" in workflow
    assert "scripts/run_followup_performance_aggregate.py" in workflow
    assert workflow.count("Download final formal unit ") == 34


def test_analysis_is_manual_exact_s3_and_reinspects_one_successful_formal_run() -> None:
    workflow = _text(ANALYSIS)
    assert re.search(r"(?m)^on:\n  workflow_dispatch:\n", workflow)
    assert "push:" not in workflow
    assert "pull_request:" not in workflow
    assert "schedule:" not in workflow
    assert "actions: read" in workflow
    assert "contents: read" in workflow
    assert "cancel-in-progress: false" in workflow
    assert CHECKOUT in workflow
    assert SETUP in workflow
    assert DOWNLOAD in workflow
    assert UPLOAD in workflow
    assert all(value not in workflow for value in REGISTERED_VALUES)
    assert "ref: ${{ inputs.expected_s3_git_sha }}" in workflow
    assert "scripts/verify_followup_performance_analysis_lineage.py" in workflow
    assert ".github/workflows/followup-performance-formal.yml" in workflow
    assert "scripts/prepare_followup_performance_analysis_inputs.py" in workflow
    assert "scripts/run_followup_performance_analysis.py" in workflow
    assert "merge-multiple: false" in workflow
    assert "retention-days: 90" in workflow
