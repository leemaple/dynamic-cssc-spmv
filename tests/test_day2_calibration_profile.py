from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path

import pytest

from dynamic_cssc.day2_calibration_authority import FIXED_CANDIDATE_IDS, PRIMITIVE_NAMES
from dynamic_cssc.day2_calibration_profile import (
    Day2CalibrationProfileError,
    _derive_day2_profile_documents,
    propose_repository_day2_calibration_profile,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA = "a" * 40


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


def _sha256(value: object) -> str:
    content = value if isinstance(value, bytes) else _canonical(value)
    return hashlib.sha256(content).hexdigest()


def _inputs() -> tuple[dict[str, object], ...]:
    count_bundle = {
        "schema_version": "dynamic-cssc-day1a-count-bundle-v1",
        "source_git_sha": SOURCE_SHA,
        "suite_status_sha256": "5" * 64,
        "experiment_plan_sha256": "6" * 64,
        "manifest_sha256": "7" * 64,
        "measurement_kind": "predicted-proxy",
        "state_model": "persistent-strategy-snapshots",
        "evidence_scope": "synthetic-causal-count-and-exact-rotation-inventory-only",
        "rows": 4096,
        "cols": 8193,
        "effective_slots": 4096,
        "partition_rows": 4096,
        "candidate_ids": list(FIXED_CANDIDATE_IDS),
        "reference_candidate_ids": [
            item
            for item in FIXED_CANDIDATE_IDS
            if item != "packed-coo-client-lane-delta/capacity=128"
        ],
        "ablation_candidate_ids": ["packed-coo-client-lane-delta/capacity=128"],
        "metric_count_fields": ["rotations"],
        "cell_count": 1,
        "fixed_record_count": 14,
        "records": [],
    }
    rotation_inventory = {
        "schema_version": "dynamic-cssc-day1a-rotation-inventory-v1",
        "source_git_sha": SOURCE_SHA,
        "count_bundle_sha256": _sha256(count_bundle),
        "rows": 4096,
        "cols": 8193,
        "effective_slots": 4096,
        "partition_rows": 4096,
        "publication_rows": 4096,
        "publication_cols": 8193,
        "publication_effective_slots": 4096,
        "publication_partition_rows": 4096,
        "publication_domain_match": True,
        "indices_in_range": True,
        "modulo_alias_free": True,
        "day2_direct_key_plan_eligible": True,
        "required_exact_indices": [-3, -1, 1, 7],
        "measured_counts_by_exact_index": [[-3, 1], [-1, 1], [1, 1], [7, 1]],
        "candidate_required_exact_indices": [],
    }
    receipt = {
        "schema_version": "dynamic-cssc-day1a-authority-receipt-v1",
        "status": "pass",
        "evidence_scope": "synthetic-causal-count-and-exact-rotation-inventory-only",
        "source_git_sha": SOURCE_SHA,
        "suite_status_sha256": "5" * 64,
        "count_bundle_schema_version": "dynamic-cssc-day1a-count-bundle-v1",
        "count_bundle_sha256": _sha256(count_bundle),
        "rotation_inventory_schema_version": "dynamic-cssc-day1a-rotation-inventory-v1",
        "rotation_inventory_sha256": _sha256(rotation_inventory),
        "cell_count": 1,
        "fixed_record_count": 14,
        "day1a_count_evidence_authorized": True,
        "day2_direct_key_plan_authorized": True,
        "publication_domain_match": True,
        "complete_cost_claim_allowed": False,
        "formal_performance_claim_allowed": False,
        "paper_verdict_allowed": False,
        "security_claim_allowed": False,
    }
    registration = {
        "schema_version": "dynamic-cssc-day1-registration-evidence-v1",
        "source_git_sha": "b" * 40,
        "run_id": 123,
        "correctness_artifact_sha256": "1" * 64,
        "accounting_evidence_sha256": "2" * 64,
        "policy_contract_sha256": (
            "a35cecd1553f53da9639a041d49d817c47bc9ae90aee269eaf2cd6f5daa8227b"
        ),
    }
    metadata = {
        "schema_version": "dynamic-cssc-day1a-github-artifact-metadata-v1",
        "repository": "leemaple/dynamic-cssc-spmv",
        "repository_id": 1_341_939_625,
        "workflow_path": ".github/workflows/day1a-publication-cost-model.yml",
        "workflow_file_sha256": "3" * 64,
        "run_id": 456,
        "run_attempt": 1,
        "event_name": "workflow_dispatch",
        "ref": "refs/heads/main",
        "head_sha": SOURCE_SHA,
        "artifact_name": f"r2-day1a-publication-{SOURCE_SHA}-20260821",
        "artifact_id": 789,
        "artifact_digest": "sha256:" + "4" * 64,
    }
    return receipt, rotation_inventory, count_bundle, registration, metadata


def _derive():
    receipt, rotation, count_bundle, registration, metadata = _inputs()
    return _derive_day2_profile_documents(
        repository_root=ROOT,
        day1a_authority_receipt=receipt,
        day1a_rotation_inventory=rotation,
        day1a_count_bundle=count_bundle,
        registration_evidence=registration,
        day1a_artifact_metadata=metadata,
    )


def test_profile_derivation_separates_pre_dispatch_plan_from_generated_key_outcomes() -> None:
    documents = _derive()
    plan = documents.rotation_key_plan

    assert plan == {
        "schema_version": "dynamic-cssc-publication-rotation-key-plan-v2",
        "inventory_source_schema_version": "dynamic-cssc-day1a-rotation-inventory-v1",
        "day1a_authority_receipt_sha256": _sha256(_inputs()[0]),
        "day1a_inventory_sha256": _sha256(_inputs()[1]),
        "effective_slots": 4096,
        "required_exact_indices": [-3, -1, 1, 7],
        "key_plan_kind": "direct-exact-index-v1",
        "planned_exact_indices": [-3, -1, 1, 7],
        "composite_decompositions": [],
        "eval_rotate_case_ids": ["index=-3", "index=-1", "index=1", "index=7"],
    }
    assert not {
        "generated_exact_indices",
        "serialized_rotation_key_inventory_sha256",
        "serialized_rotation_key_bytes",
        "eval_mult_key_generated",
        "serialized_eval_mult_key_sha256",
        "serialized_eval_mult_key_bytes",
    } & set(plan)


def test_profile_derivation_freezes_exact_probe_cases_and_profile_anchor_retrieval() -> None:
    documents = _derive()
    profiles = documents.operation_profile_set
    anchor = documents.profile_anchor

    assert profiles["schema_version"] == "dynamic-cssc-publication-operation-profile-set-v2"
    assert profiles["primitive_names"] == list(PRIMITIVE_NAMES)
    assert len(profiles["profiles"]) == 14
    by_name = {item["primitive_name"]: item for item in profiles["profiles"]}
    assert [item["case_id"] for item in by_name["eval_rotate"]["cases"]] == [
        "index=-3",
        "index=-1",
        "index=1",
        "index=7",
    ]
    for primitive_name, profile in by_name.items():
        expected_count = (
            4096
            if primitive_name
            in {
                "client_merge",
                "client_reorder_element",
                "mask_map_element",
                "mask_random_element",
                "query_vector_pack",
            }
            else 1
        )
        assert {case["operation_count"] for case in profile["cases"]} == {expected_count}
        assert all("input_fixture_contract_sha256" in case for case in profile["cases"])
        assert all("input_fixture_sha256" not in case for case in profile["cases"])

    assert anchor["schema_version"] == "dynamic-cssc-day2-calibration-profile-anchor-v3"
    assert anchor["rotation_key_plan_sha256"] == _sha256(documents.rotation_key_plan)
    assert anchor["operation_profile_set_sha256"] == _sha256(profiles)
    assert anchor["contract_bindings_sha256"] == _sha256(documents.contract_bindings)
    assert anchor["day1a_workflow_run_id"] == 456
    assert anchor["day1a_artifact_id"] == 789
    assert anchor["day1a_artifact_name"] == f"r2-day1a-publication-{SOURCE_SHA}-20260821"
    assert anchor["day1a_artifact_digest"] == "sha256:" + "4" * 64


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda values: values[0].update(day2_direct_key_plan_authorized=False), "authorized"),
        (lambda values: values[1].update(modulo_alias_free=False), "modulo"),
        (lambda values: values[1]["required_exact_indices"].append(7), "canonical"),
        (lambda values: values[2]["candidate_ids"].pop(), "candidate"),
        (lambda values: values[4].update(head_sha="c" * 40), "head SHA"),
    ],
)
def test_profile_derivation_rejects_spliced_day1a_and_provider_inputs(
    mutation: object,
    message: str,
) -> None:
    values = list(_inputs())
    mutation(values)

    with pytest.raises(Day2CalibrationProfileError, match=message):
        _derive_day2_profile_documents(
            repository_root=ROOT,
            day1a_authority_receipt=values[0],
            day1a_rotation_inventory=values[1],
            day1a_count_bundle=values[2],
            registration_evidence=values[3],
            day1a_artifact_metadata=values[4],
        )


def test_public_profile_proposal_interface_accepts_only_artifact_paths() -> None:
    assert tuple(inspect.signature(propose_repository_day2_calibration_profile).parameters) == (
        "day1a_directory",
        "github_artifact_metadata_path",
        "output_directory",
    )
