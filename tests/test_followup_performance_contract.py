from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from dynamic_cssc import followup_performance_contract as contract_module
from dynamic_cssc.followup_performance_contract import (
    FOLLOWUP_ARTIFACT_PREFIX,
    FOLLOWUP_BASELINE_SHA256,
    FOLLOWUP_ENVELOPE_SCHEMA,
    FOLLOWUP_STAGE1_COMMIT_SHA,
    FOLLOWUP_STAGE1_MANIFEST_SHA256,
    FOLLOWUP_STAGE1_PLAN_SHA256,
    FOLLOWUP_STUDY_ID,
    FollowupContractError,
    admit_followup_control_inner_payload,
    build_followup_unit_identity,
    followup_artifact_name,
    followup_inherited_unit_attempt_ordinal,
    inspect_followup_outer_envelope,
    inspect_followup_stage1,
    materialize_followup_scientific_plan,
    seal_followup_inner_payload,
)

ROOT = Path(__file__).resolve().parents[1]
SENTINEL_S1 = "1" * 40
SENTINEL_S2 = "2" * 40


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _control_inner() -> bytes:
    return _canonical(
        {
            "authority": False,
            "result": "sentinel-only",
            "schema_version": "dynamic-cssc-followup-performance-ci-provenance-v1",
            "study_id": FOLLOWUP_STUDY_ID,
        }
    )


def _sealed_control():
    unit_bytes, unit_sha256 = build_followup_unit_identity(
        unit_kind="control-ci",
        unit_attempt_ordinal=1,
        scope={"branch": "sentinel-only", "provider_run_id": 17},
    )
    admission = admit_followup_control_inner_payload(
        inner_role="ci-provenance",
        inner_bytes=_control_inner(),
    )
    envelope = seal_followup_inner_payload(
        admission,
        experiment_source_s1_sha=SENTINEL_S1,
        evidence_freeze_s2_sha=SENTINEL_S2,
        unit_kind="control-ci",
        unit_identity_sha256=unit_sha256,
        unit_attempt_ordinal=1,
    )
    return unit_bytes, unit_sha256, envelope


def test_exact_stage1_and_materialized_baseline_reproduce_without_executing_seeds() -> None:
    inspection = inspect_followup_stage1(ROOT)

    assert inspection.stage1_commit_sha == FOLLOWUP_STAGE1_COMMIT_SHA
    assert inspection.stage1_plan_sha256 == FOLLOWUP_STAGE1_PLAN_SHA256
    assert inspection.stage1_manifest_sha256 == FOLLOWUP_STAGE1_MANIFEST_SHA256
    assert inspection.materialized_baseline_sha256 == FOLLOWUP_BASELINE_SHA256
    assert inspection.registered_value_change_count == 5
    assert inspection.predecessor_top_level_key_count == 21


def test_closed_plan_schema_is_the_exact_stage1_json_value() -> None:
    plan = json.loads((ROOT / "config/followup-performance-study.json").read_bytes())
    schema = json.loads(
        (ROOT / "schemas/followup-performance-study-v1.schema.json").read_bytes()
    )

    assert set(schema) == {"$id", "$schema", "const", "description", "title"}
    assert schema["const"] == plan
    assert hashlib.sha256(
        (ROOT / "config/followup-performance-study.json").read_bytes()
    ).hexdigest() == FOLLOWUP_STAGE1_PLAN_SHA256


def test_materialized_scientific_plan_exposes_only_the_frozen_scalar_profile() -> None:
    materialized = materialize_followup_scientific_plan(ROOT)
    plan = json.loads(materialized.machine_plan_bytes)

    assert materialized.machine_plan_sha256 == FOLLOWUP_BASELINE_SHA256
    assert materialized.scientific_profile.profile_id == FOLLOWUP_STUDY_ID
    assert materialized.scientific_profile.qualification_seed == plan["qualification"]["seed"]
    assert list(materialized.scientific_profile.formal_seeds) == plan["synthetic"]["seeds"]
    assert materialized.scientific_profile.query_vector_seed == plan["query_vector"]["seed"]


def test_stage1_inspector_rejects_duplicate_plan_key_before_semantic_comparison(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_reader = contract_module._read_regular_file

    def attacked_reader(root: Path, relative_path: str) -> bytes:
        if relative_path == "config/followup-performance-study.json":
            return b'{"schema_version":"x","schema_version":"y"}\n'
        return original_reader(root, relative_path)

    monkeypatch.setattr(contract_module, "_read_regular_file", attacked_reader)
    with pytest.raises(FollowupContractError, match="Stage-1 plan bytes changed"):
        inspect_followup_stage1(ROOT)


def test_stage1_inspector_rejects_manifested_object_substitution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_reader = contract_module._read_regular_file

    def attacked_reader(root: Path, relative_path: str) -> bytes:
        payload = original_reader(root, relative_path)
        if relative_path == "docs/paper/followup-performance-claim-ledger.md":
            return payload + b"substitution\n"
        return payload

    monkeypatch.setattr(contract_module, "_read_regular_file", attacked_reader)
    with pytest.raises(FollowupContractError, match="manifest entry differs"):
        inspect_followup_stage1(ROOT)


def test_outer_envelope_round_trip_binds_separate_inner_bytes() -> None:
    unit_bytes, unit_sha256, envelope = _sealed_control()

    assert hashlib.sha256(unit_bytes).hexdigest() == unit_sha256
    assert envelope.document["schema_version"] == FOLLOWUP_ENVELOPE_SCHEMA
    assert envelope.document["authority"] is False
    assert envelope.document["inner_sha256"] == hashlib.sha256(_control_inner()).hexdigest()
    assert envelope.document["stage1_commit_sha"] == FOLLOWUP_STAGE1_COMMIT_SHA
    assert envelope.document["stage1_plan_sha256"] == FOLLOWUP_STAGE1_PLAN_SHA256
    assert envelope.document["materialized_predecessor_baseline_sha256"] == (
        FOLLOWUP_BASELINE_SHA256
    )

    inspected = inspect_followup_outer_envelope(
        envelope.document_bytes,
        envelope.inner_bytes,
        expected_experiment_source_s1_sha=SENTINEL_S1,
        expected_evidence_freeze_s2_sha=SENTINEL_S2,
    )
    assert inspected == envelope


def test_raw_predecessor_rejects_before_inner_decode() -> None:
    predecessor = (ROOT / "config/route-a-publication-plan.json").read_bytes()

    with pytest.raises(FollowupContractError, match="raw predecessor"):
        inspect_followup_outer_envelope(predecessor, predecessor)


def test_control_admission_rejects_a_route_a_schema_even_when_other_fields_are_forged() -> None:
    forged = _canonical(
        {
            "authority": False,
            "schema_version": "dynamic-cssc-route-a-registration-evidence-v1",
            "study_id": FOLLOWUP_STUDY_ID,
        }
    )

    with pytest.raises(FollowupContractError, match="follow-up-only identity"):
        admit_followup_control_inner_payload(
            inner_role="descriptive-registration",
            inner_bytes=forged,
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("extra-field", "raw predecessor"),
        ("authority-true", "exact follow-up lineage"),
        ("wrong-inner", "separately retained inner bytes"),
        ("wrong-role", "incompatible"),
    ],
)
def test_outer_envelope_fails_closed_on_identity_or_payload_splice(
    mutation: str,
    message: str,
) -> None:
    _, _, envelope = _sealed_control()
    document = dict(envelope.document)
    inner_bytes = envelope.inner_bytes
    if mutation == "extra-field":
        document["caller_added"] = False
    elif mutation == "authority-true":
        document["authority"] = True
    elif mutation == "wrong-inner":
        inner_bytes += b"x"
    elif mutation == "wrong-role":
        document["inner_role"] = "descriptive-registration"
    else:  # pragma: no cover - parametrization is closed
        raise AssertionError(mutation)

    with pytest.raises(FollowupContractError, match=message):
        inspect_followup_outer_envelope(_canonical(document), inner_bytes)


def test_unit_attempt_domain_matches_the_single_formal_replacement_rule() -> None:
    _, formal_retry_identity = build_followup_unit_identity(
        unit_kind="formal-synthetic",
        unit_attempt_ordinal=2,
        scope={"sentinel": 99},
    )
    assert len(formal_retry_identity) == 64

    with pytest.raises(FollowupContractError, match="retry domain"):
        build_followup_unit_identity(
            unit_kind="qualification-q1",
            unit_attempt_ordinal=2,
            scope={"sentinel": 99},
        )
    with pytest.raises(FollowupContractError, match="retry domain"):
        build_followup_unit_identity(
            unit_kind="formal-terminal-admission",
            unit_attempt_ordinal=2,
            scope={"sentinel": 99},
        )


def test_outer_attempts_map_once_onto_the_inherited_scientific_domain() -> None:
    assert followup_inherited_unit_attempt_ordinal(
        unit_kind="formal-acquisition",
        unit_attempt_ordinal=1,
    ) == 0
    assert followup_inherited_unit_attempt_ordinal(
        unit_kind="formal-synthetic",
        unit_attempt_ordinal=2,
    ) == 1
    assert followup_inherited_unit_attempt_ordinal(
        unit_kind="control-ci",
        unit_attempt_ordinal=1,
    ) == 0

    with pytest.raises(FollowupContractError, match="retry domain"):
        followup_inherited_unit_attempt_ordinal(
            unit_kind="formal-terminal-admission",
            unit_attempt_ordinal=2,
        )


def test_followup_artifact_name_has_no_predecessor_namespace() -> None:
    name = followup_artifact_name(
        unit_kind="formal-synthetic",
        unit_identity_sha256="a" * 64,
        unit_attempt_ordinal=1,
    )

    assert name == f"{FOLLOWUP_ARTIFACT_PREFIX}formal-synthetic-{'a' * 16}-attempt-1"
    assert "route-a" not in name


def test_stage2_contract_source_neither_embeds_registered_seeds_nor_imports_generators() -> None:
    source = (ROOT / "src/dynamic_cssc/followup_performance_contract.py").read_text(
        encoding="utf-8"
    )

    for registered_seed in ("20260901", "20260902", "20260903", "20260904", "2026090202"):
        assert registered_seed not in source
    assert "generate_route_a_" not in source
    assert "evaluate_route_a_" not in source
