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
FORMAL = WORKFLOWS / "followup-performance-formal-unit.yml"
TERMINAL = WORKFLOWS / "followup-performance-terminal.yml"
ANALYSIS = WORKFLOWS / "followup-performance-analysis.yml"
FORMAL_ACTION = ROOT / ".github/actions/followup-formal-unit/action.yml"
FORMAL_ADMISSION_ACTION = ROOT / ".github/actions/followup-campaign-run-admission/action.yml"
QUALIFICATION_ADMISSION_ACTION = (
    ROOT / ".github/actions/followup-qualification-run-admission/action.yml"
)
TERMINAL_ADMISSION_ACTION = (
    ROOT / ".github/actions/followup-terminal-run-admission/action.yml"
)
ANALYSIS_ADMISSION_ACTION = (
    ROOT / ".github/actions/followup-analysis-run-admission/action.yml"
)
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
    assert "contents: write" not in workflow
    assert "expected_authority_claim_oid" in workflow
    assert "./.github/actions/followup-qualification-run-admission" in workflow
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
    assert "expected_campaign_id" in workflow
    assert "expected_reservation_oid" in workflow
    assert "formal_unit_ordinal" in workflow
    assert "unit_attempt_ordinal" in workflow
    assert "contents: write" not in workflow
    assert "./.github/actions/followup-formal-unit" in workflow


def test_run_admission_actions_require_external_watch_binding_before_science() -> None:
    qualification = _text(QUALIFICATION)
    formal = _text(FORMAL)
    terminal = _text(TERMINAL)
    analysis = _text(ANALYSIS)
    qualification_action = _text(QUALIFICATION_ADMISSION_ACTION)
    formal_action = _text(FORMAL_ADMISSION_ACTION)
    terminal_action = _text(TERMINAL_ADMISSION_ACTION)
    analysis_action = _text(ANALYSIS_ADMISSION_ACTION)
    for action, authority_ref, verifier in (
        (
            qualification_action,
            "dynamic-cssc-followup-performance-qualification-authority-v1",
            "scripts/verify_followup_qualification_run_admission.py",
        ),
        (
            formal_action,
            "dynamic-cssc-followup-performance-formal-authority-v1",
            "scripts/verify_followup_campaign_run_admission.py",
        ),
        (
            terminal_action,
            "dynamic-cssc-followup-performance-formal-terminal-v1",
            "scripts/verify_followup_terminal_run_admission.py",
        ),
        (
            analysis_action,
            "dynamic-cssc-followup-performance-analysis-v1",
            "scripts/verify_followup_analysis_run_admission.py",
        ),
    ):
        assert "test \"$GITHUB_RUN_ATTEMPT\" = 1" in action
        assert authority_ref in action
        assert verifier in action
        assert "updateRefs" not in action
        assert "contents: write" not in action
    assert qualification.index(
        "Require the external mandatory watcher before registered-seed execution"
    ) < qualification.index(
        "Run q1 simulator producer"
    )
    assert formal.index("Check out exact S2 for provider admission") < formal.index(
        "Execute the bound producer"
    )
    assert terminal.index("Verify terminal claim and externally armed watcher") < (
        terminal.index("Independently admit the exact seventeen-unit set")
    )
    assert analysis.index("Verify analysis claim and externally armed watcher") < (
        analysis.index("Reinspect evidence and produce bounded descriptive analysis")
    )


def test_formal_unit_workflow_is_one_bound_two_job_run_for_all_seventeen_specs() -> None:
    workflow = _text(FORMAL)
    specs = followup_formal_unit_specs(SENTINEL_PROFILE)
    assert len(specs) == 17
    assert tuple(spec.ordinal for spec in specs) == tuple(range(17))
    assert re.findall(r"(?m)^  ([a-z]+):$", workflow) == ["producer", "guard"]
    assert workflow.count(
        "    timeout-minutes: ${{ inputs.expected_reservation_minutes }}"
    ) == 2
    assert max(spec.reservation_minutes for spec in specs) == 50
    assert "    needs: producer" in workflow
    assert workflow.count("expected_reservation_oid") >= 3
    assert workflow.count("expected_reservation_minutes") >= 3
    assert workflow.count("expected_job_token") >= 3
    assert workflow.count("unit_attempt_ordinal") >= 3


def test_formal_unit_phases_share_one_pinned_exact_s1_action() -> None:
    workflow = _text(FORMAL)
    action = _text(FORMAL_ACTION)
    assert workflow.count(CHECKOUT) == 2
    assert action.count(CHECKOUT) == 1
    assert action.count(SETUP) == 1
    assert action.count(UPLOAD) == 1
    assert action.count(DOWNLOAD) == 2
    assert "scripts/run_followup_performance_formal_unit.py" in action
    assert "./.github/actions/followup-formal-provider-deadline" in action
    assert "scripts/verify_followup_formal_phase_deadline.py" in _text(
        ROOT / ".github/actions/followup-formal-provider-deadline/action.yml"
    )
    assert action.count("timeout --signal=TERM --kill-after=10s") == 3
    assert "checkpoint: before-formal-execution" in action
    assert "checkpoint: before-phase-artifact-upload" in action
    assert "checkpoint: after-phase-artifact-upload" in action
    assert "scripts/verify_followup_performance_lineage.py" in action
    assert "phase: private-handoff" in workflow
    assert "phase: guarded-final" in workflow
    assert "retention-days: '1'" in workflow
    assert "retention-days: '90'" in workflow
    assert "formal-terminal-admission" not in workflow
    assert "formal-aggregate" not in workflow


def test_analysis_is_manual_exact_s3_and_rebinds_terminal_campaign_evidence() -> None:
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
    assert DOWNLOAD not in workflow
    assert UPLOAD in workflow
    assert all(value not in workflow for value in REGISTERED_VALUES)
    assert "ref: ${{ inputs.expected_s3_git_sha }}" in workflow
    assert "expected_analysis_claim_oid" in workflow
    assert "expected_campaign_id" in workflow
    assert "./.github/actions/followup-analysis-run-admission" in workflow
    assert "scripts/verify_followup_performance_analysis_lineage.py" in workflow
    assert ".github/workflows/followup-performance-formal.yml" not in workflow
    assert "scripts/prepare_followup_performance_analysis_inputs.py" in workflow
    assert "scripts/run_followup_performance_analysis.py" in workflow
    assert "--campaign-evidence-root" in workflow
    assert "--terminal-provider-run-id" in workflow
    assert "timeout --signal=TERM --kill-after=10s" in workflow
    assert "FOLLOWUP_ANALYSIS_PHASE_RECEIPT_V1=" in workflow
    assert "timeout-minutes: 30" in workflow
    assert "retention-days: 90" in workflow
