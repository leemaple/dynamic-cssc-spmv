from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.verify_followup_campaign_run_admission as admission_script
from dynamic_cssc.followup_performance_campaign import (
    FollowupCampaignError,
    arm_followup_campaign_watch,
    bind_followup_campaign_run,
    build_followup_campaign_selection,
    close_followup_campaign_no_go,
    commit_followup_campaign_unit,
    followup_formal_matrix_sha256,
    inspect_followup_campaign_run_admission,
    inspect_followup_campaign_selection,
    inspect_followup_campaign_state,
    open_followup_campaign_state,
    record_followup_provider_failure,
    reserve_followup_campaign_unit,
)
from dynamic_cssc.followup_performance_formal_matrix import followup_formal_unit_specs
from dynamic_cssc.route_a_scientific_profile import RouteAScientificProfile

PLAN = b'{"campaign_state_sentinel":true}\n'
PROFILE = RouteAScientificProfile(
    profile_id="campaign-state-sentinel",
    qualification_seed=95_001,
    formal_seeds=(95_002, 95_003, 95_004),
    query_vector_seed=9_500_102,
    machine_plan_sha256=hashlib.sha256(PLAN).hexdigest(),
)


def _open():  # type: ignore[no-untyped-def]
    return open_followup_campaign_state(
        experiment_source_s1_sha="1" * 40,
        evidence_freeze_s2_sha="2" * 40,
        compatibility_receipt_sha256="3" * 64,
        qualification_run_id=7001,
        qualification_q6_artifact_id=8001,
        qualification_q6_artifact_digest=f"sha256:{'4' * 64}",
        scientific_profile=PROFILE,
    )


def _armed(ordinal: int = 0, *, attempt: int = 1):  # type: ignore[no-untyped-def]
    previous = _open()
    spec = followup_formal_unit_specs(PROFILE)[ordinal]
    if ordinal != 0:
        raise AssertionError("test helper only constructs the first unit")
    reserved = reserve_followup_campaign_unit(
        previous,
        spec,
        unit_attempt_ordinal=attempt,
    )
    bound = bind_followup_campaign_run(reserved, provider_run_id=9001)
    return arm_followup_campaign_watch(
        bound,
        watcher_session_sha256="5" * 64,
    )


def test_campaign_open_binds_one_reproducible_matrix_and_qualification() -> None:
    opened = _open()

    assert opened.state == "campaign-open"
    assert opened.sequence == 0
    assert opened.document["retry_used"] is False
    assert opened.document["formal_matrix_sha256"] == followup_formal_matrix_sha256(
        PROFILE
    )
    assert inspect_followup_campaign_state(opened.document_bytes) == opened


def test_nominal_unit_requires_reserve_bind_watch_then_commit() -> None:
    specs = followup_formal_unit_specs(PROFILE)
    reserved = reserve_followup_campaign_unit(
        _open(),
        specs[0],
        unit_attempt_ordinal=1,
    )
    bound = bind_followup_campaign_run(reserved, provider_run_id=9001)
    armed = arm_followup_campaign_watch(
        bound,
        watcher_session_sha256="5" * 64,
    )
    committed = commit_followup_campaign_unit(
        armed,
        watcher_receipt_sha256="6" * 64,
        artifact_id=9101,
        artifact_name="followup-performance-v1-formal-acquisition-sentinel",
        artifact_provider_digest=f"sha256:{'7' * 64}",
        unit_output_envelope_sha256="8" * 64,
    )
    next_reserved = reserve_followup_campaign_unit(
        committed,
        specs[1],
        unit_attempt_ordinal=1,
    )

    assert [
        reserved.state,
        bound.state,
        armed.state,
        committed.state,
        next_reserved.state,
    ] == [
        "unit-reserved",
        "run-bound",
        "watch-armed",
        "unit-committed",
        "unit-reserved",
    ]
    assert next_reserved.document["unit_ordinal_or_null"] == 1

    campaign_id = reserved.document["campaign_id"]
    assert type(campaign_id) is str
    admitted = inspect_followup_campaign_run_admission(
        reserved.document_bytes,
        bound.document_bytes,
        armed.document_bytes,
        scientific_profile=PROFILE,
        expected_campaign_id=campaign_id,
        expected_unit_ordinal=0,
        expected_unit_attempt_ordinal=1,
        expected_provider_run_id=9001,
    )
    assert admitted == armed


def test_only_closed_provider_failure_can_consume_the_single_replacement() -> None:
    spec = followup_formal_unit_specs(PROFILE)[0]
    failed = record_followup_provider_failure(
        _armed(),
        provider_failure_class="hosted-runner-loss-or-shutdown",
        provider_failure_evidence_sha256="9" * 64,
        watcher_receipt_sha256="a" * 64,
    )
    replacement = reserve_followup_campaign_unit(
        failed,
        spec,
        unit_attempt_ordinal=2,
    )

    assert failed.state == "unit-provider-failed"
    assert replacement.document["retry_used"] is True
    assert replacement.document["unit_attempt_ordinal_or_null"] == 2

    rebound = bind_followup_campaign_run(replacement, provider_run_id=9002)
    rearmed = arm_followup_campaign_watch(
        rebound,
        watcher_session_sha256="b" * 64,
    )
    with pytest.raises(FollowupCampaignError, match="already consumed"):
        record_followup_provider_failure(
            rearmed,
            provider_failure_class="hosted-runner-loss-or-shutdown",
            provider_failure_evidence_sha256="c" * 64,
            watcher_receipt_sha256="d" * 64,
        )


def test_correctness_or_ambiguous_failure_cannot_enter_the_retry_path() -> None:
    with pytest.raises(FollowupCampaignError, match="not replacement-eligible"):
        record_followup_provider_failure(
            _armed(),
            provider_failure_class="guard-failure",
            provider_failure_evidence_sha256="9" * 64,
            watcher_receipt_sha256="a" * 64,
        )

    no_go = close_followup_campaign_no_go(
        _armed(),
        terminal_reason_code="scientific-or-guard-failure",
    )
    assert no_go.state == "campaign-no-go"


def test_campaign_id_or_field_splice_rejects_independent_reinspection() -> None:
    document = dict(_open().document)
    document["campaign_id"] = "f" * 64
    content = (
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")

    with pytest.raises(FollowupCampaignError, match="does not reproduce"):
        inspect_followup_campaign_state(content)


def _complete_campaign(*, replacement_ordinal: int | None = None):  # type: ignore[no-untyped-def]
    previous = _open()
    committed = []
    admissions = []
    run_id = 10_000
    for spec in followup_formal_unit_specs(PROFILE):
        reserved = reserve_followup_campaign_unit(
            previous,
            spec,
            unit_attempt_ordinal=1,
        )
        bound = bind_followup_campaign_run(reserved, provider_run_id=run_id)
        armed = arm_followup_campaign_watch(
            bound,
            watcher_session_sha256=f"{run_id + 1:064x}",
        )
        if spec.ordinal == replacement_ordinal:
            failed = record_followup_provider_failure(
                armed,
                provider_failure_class="hosted-runner-loss-or-shutdown",
                provider_failure_evidence_sha256=f"{run_id + 2:064x}",
                watcher_receipt_sha256=f"{run_id + 3:064x}",
            )
            run_id += 10
            reserved = reserve_followup_campaign_unit(
                failed,
                spec,
                unit_attempt_ordinal=2,
            )
            bound = bind_followup_campaign_run(reserved, provider_run_id=run_id)
            armed = arm_followup_campaign_watch(
                bound,
                watcher_session_sha256=f"{run_id + 1:064x}",
            )
        state = commit_followup_campaign_unit(
            armed,
            watcher_receipt_sha256=f"{run_id + 2:064x}",
            artifact_id=20_000 + spec.ordinal,
            artifact_name=(
                f"followup-performance-v1-{spec.unit_kind}-{spec.ordinal:02d}"
            ),
            artifact_provider_digest=f"sha256:{30_000 + spec.ordinal:064x}",
            unit_output_envelope_sha256=f"{40_000 + spec.ordinal:064x}",
        )
        committed.append(state)
        admissions.append(f"{50_000 + spec.ordinal:064x}")
        previous = state
        run_id += 10
    return tuple(committed), tuple(admissions)


def test_campaign_selection_closes_all_final_attempts_and_one_retry() -> None:
    states, admissions = _complete_campaign(replacement_ordinal=6)
    selection = build_followup_campaign_selection(
        states,
        admissions,
        scientific_profile=PROFILE,
    )
    reinspected = inspect_followup_campaign_selection(
        selection.document_bytes,
        tuple(state.document_bytes for state in states),
        scientific_profile=PROFILE,
    )

    assert reinspected == selection
    assert selection.document["formal_unit_count"] == 17
    assert selection.document["replacement_attempt_used"] is True
    assert selection.document["replacement_unit_ordinal_or_null"] == 6
    assert selection.units[6]["unit_attempt_ordinal"] == 2
    assert len({unit["provider_run_id"] for unit in selection.units}) == 17


def test_campaign_selection_rejects_duplicate_run_admission() -> None:
    states, admissions = _complete_campaign()
    duplicate = list(admissions)
    duplicate[1] = duplicate[0]

    with pytest.raises(FollowupCampaignError, match="reuses"):
        build_followup_campaign_selection(
            states,
            tuple(duplicate),
            scientific_profile=PROFILE,
        )


def test_campaign_admission_script_rebuilds_reserve_bind_watch_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    opened = _open()
    spec = followup_formal_unit_specs(PROFILE)[0]
    reserved = reserve_followup_campaign_unit(
        opened,
        spec,
        unit_attempt_ordinal=1,
    )
    bound = bind_followup_campaign_run(reserved, provider_run_id=9001)
    armed = arm_followup_campaign_watch(
        bound,
        watcher_session_sha256="5" * 64,
    )
    reservation_oid = "a" * 40
    binding_oid = "b" * 40
    watch_oid = "c" * 40
    tree_oid = "e" * 40

    def write(name: str, value: dict[str, object]) -> Path:
        path = tmp_path / name
        path.write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")),
            encoding="ascii",
        )
        return path.resolve()

    ref_path = write(
        "ref.json",
        {
            "object": {"sha": watch_oid, "type": "commit"},
            "ref": admission_script.FOLLOWUP_FORMAL_PROGRESS_REF,
        },
    )
    reservation_path = write(
        "reservation.json",
        {
            "message": reserved.document_bytes.decode("ascii"),
            "parents": [{"sha": "d" * 40}],
            "sha": reservation_oid,
            "tree": {"sha": tree_oid},
        },
    )
    binding_path = write(
        "binding.json",
        {
            "message": bound.document_bytes.decode("ascii"),
            "parents": [{"sha": reservation_oid}],
            "sha": binding_oid,
            "tree": {"sha": tree_oid},
        },
    )
    watch_path = write(
        "watch.json",
        {
            "message": armed.document_bytes.decode("ascii"),
            "parents": [{"sha": binding_oid}],
            "sha": watch_oid,
            "tree": {"sha": tree_oid},
        },
    )

    def fake_git(_root: Path, *arguments: str) -> str:
        if arguments == ("rev-parse", "HEAD"):
            return "2" * 40
        if arguments == ("status", "--porcelain=v1", "--untracked-files=no"):
            return ""
        if arguments == ("rev-parse", "HEAD^{tree}"):
            return tree_oid
        raise AssertionError(arguments)

    monkeypatch.setattr(admission_script, "_git", fake_git)
    monkeypatch.setattr(
        admission_script,
        "materialize_followup_scientific_plan",
        lambda _root: SimpleNamespace(scientific_profile=PROFILE),
    )
    arguments = argparse.Namespace(
        repository_root=tmp_path,
        ref_json=ref_path,
        reservation_commit_json=reservation_path,
        binding_commit_json=binding_path,
        watch_commit_json=watch_path,
        expected_reservation_oid=reservation_oid,
        expected_reservation_minutes=20,
        expected_campaign_id=opened.document["campaign_id"],
        expected_s1="1" * 40,
        expected_s2="2" * 40,
        expected_compatibility="3" * 64,
        expected_unit_ordinal=0,
        expected_unit_attempt_ordinal=1,
        expected_job_token=spec.job_token,
        expected_provider_run_id=9001,
    )

    assert admission_script._main(arguments) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["watch_armed_oid"] == watch_oid
    assert output["unit_kind"] == "formal-acquisition"

    write(
        "ref.json",
        {
            "object": {"sha": binding_oid, "type": "commit"},
            "ref": admission_script.FOLLOWUP_FORMAL_PROGRESS_REF,
        },
    )
    with pytest.raises(FollowupCampaignError, match="watch commit provider topology"):
        admission_script._main(arguments)
