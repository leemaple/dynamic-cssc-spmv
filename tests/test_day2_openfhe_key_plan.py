from __future__ import annotations

import hashlib
import inspect
import json
from dataclasses import replace

import pytest

import dynamic_cssc.day2_calibration_authority as authority_module
import dynamic_cssc.day2_openfhe_key_plan as plan_module
from dynamic_cssc.day2_openfhe_key_plan import (
    DAY2_OPENFHE_KEY_PLAN_RECEIPT_SCHEMA,
    Day2OpenFHEKeyPlanCapability,
    Day2OpenFHEKeyPlanError,
    abandon_day2_openfhe_key_plan,
    claim_day2_openfhe_key_plan,
    describe_day2_openfhe_key_plan,
    issue_repository_day2_openfhe_key_plan,
)


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


def _plan_bytes() -> bytes:
    indices = (-2, -1, 1, 2)
    return _canonical(
        {
            "composite_decompositions": [],
            "day1a_authority_receipt_sha256": "6" * 64,
            "day1a_inventory_sha256": "7" * 64,
            "effective_slots": 4096,
            "eval_rotate_case_ids": [f"index={index}" for index in indices],
            "inventory_source_schema_version": (
                "dynamic-cssc-day1a-rotation-inventory-v1"
            ),
            "key_plan_kind": "direct-exact-index-v1",
            "planned_exact_indices": list(indices),
            "required_exact_indices": list(indices),
            "schema_version": "dynamic-cssc-publication-rotation-key-plan-v2",
        }
    )


def _authority(
    plan_bytes: bytes,
    *,
    outer_archive_sha256: str = "2" * 64,
) -> authority_module.Day2CalibrationAuthority:
    return authority_module._mint_repository_calibration_authority(
        source_git_sha="1" * 40,
        outer_archive_sha256=outer_archive_sha256,
        raw_measurement_blocks_sha256="3" * 64,
        calibration_projection_sha256="4" * 64,
        rotation_key_plan_sha256=hashlib.sha256(plan_bytes).hexdigest(),
        serialized_object_size_profile_sha256="5" * 64,
        ciphertext_bytes=100,
        f1m_random_zero_sum_ciphertext_bytes=101,
        f1m_encrypted_zero_dummy_ciphertext_bytes=102,
        serialized_rotation_key_inventory_bytes=103,
        serialized_eval_mult_key_bytes=104,
    )


def test_repository_issuer_owns_authority_and_mints_one_exact_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan_bytes = _plan_bytes()
    authority = _authority(plan_bytes)
    calls = 0

    def repository_authority() -> authority_module.Day2CalibrationAuthority:
        nonlocal calls
        calls += 1
        return authority

    monkeypatch.setattr(
        plan_module,
        "repository_day2_calibration_authority",
        repository_authority,
    )

    assert tuple(
        inspect.signature(issue_repository_day2_openfhe_key_plan).parameters
    ) == ("rotation_key_plan_bytes",)
    capability = issue_repository_day2_openfhe_key_plan(plan_bytes)
    receipt = describe_day2_openfhe_key_plan(capability)
    document = receipt.to_document()

    assert calls == 2
    assert document["schema_version"] == DAY2_OPENFHE_KEY_PLAN_RECEIPT_SCHEMA
    assert document["day2_direct_key_plan_authorized"] is True
    assert document["day2_outer_archive_sha256"] == "2" * 64
    assert document["day1a_authority_receipt_sha256"] == "6" * 64
    assert document["day1a_inventory_sha256"] == "7" * 64
    assert document["required_exact_indices"] == [-2, -1, 1, 2]
    for denied in (
        "complete_cost_claim_allowed",
        "formal_authority_granted",
        "heldout_dispatch_authorized",
        "performance_claim_allowed",
        "publication_authority",
        "runtime_admission_granted",
        "security_claim_allowed",
    ):
        assert document[denied] is False
    with pytest.raises(TypeError, match="repository-minted"):
        Day2OpenFHEKeyPlanCapability()
    with pytest.raises(TypeError, match="not a caller boolean"):
        bool(capability)

    claimed = claim_day2_openfhe_key_plan(capability)

    assert claimed.receipt is receipt
    assert claimed.key_generation_plan.rotation_key_plan_bytes == plan_bytes
    assert claimed.key_generation_plan.rotation_key_plan_sha256 == (
        authority.rotation_key_plan_sha256
    )
    assert capability._binding is None
    with pytest.raises(Day2OpenFHEKeyPlanError, match="absent or consumed"):
        claim_day2_openfhe_key_plan(capability)


def test_issuer_rejects_a_canonical_plan_not_bound_by_final_day2() -> None:
    plan_bytes = _plan_bytes()
    authority = authority_module._mint_repository_calibration_authority(
        source_git_sha="1" * 40,
        outer_archive_sha256="2" * 64,
        raw_measurement_blocks_sha256="3" * 64,
        calibration_projection_sha256="4" * 64,
        rotation_key_plan_sha256="f" * 64,
        serialized_object_size_profile_sha256="5" * 64,
        ciphertext_bytes=100,
        f1m_random_zero_sum_ciphertext_bytes=101,
        f1m_encrypted_zero_dummy_ciphertext_bytes=102,
        serialized_rotation_key_inventory_bytes=103,
        serialized_eval_mult_key_bytes=104,
    )

    with pytest.raises(Day2OpenFHEKeyPlanError, match="final repository authority"):
        plan_module._issue_from_day2_authority(authority, plan_bytes)


def test_claim_fails_closed_and_releases_a_tampered_binding() -> None:
    plan_bytes = _plan_bytes()
    capability = plan_module._issue_from_day2_authority(
        _authority(plan_bytes),
        plan_bytes,
    )
    binding = capability._binding
    object.__setattr__(
        capability,
        "_binding",
        replace(
            binding,
            receipt=replace(
                binding.receipt,
                day1a_inventory_sha256="8" * 64,
            ),
        ),
    )

    with pytest.raises(Day2OpenFHEKeyPlanError, match="differs from its receipt"):
        claim_day2_openfhe_key_plan(capability)

    assert capability._binding is None


def test_abandon_releases_the_retained_plan_bytes() -> None:
    plan_bytes = _plan_bytes()
    capability = plan_module._issue_from_day2_authority(
        _authority(plan_bytes),
        plan_bytes,
    )

    abandon_day2_openfhe_key_plan(capability)

    assert capability._binding is None
    with pytest.raises(Day2OpenFHEKeyPlanError, match="absent or consumed"):
        describe_day2_openfhe_key_plan(capability)


def test_repository_issuer_detects_authority_change_and_consumes_the_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan_bytes = _plan_bytes()
    authorities = iter(
        (
            _authority(plan_bytes, outer_archive_sha256="2" * 64),
            _authority(plan_bytes, outer_archive_sha256="9" * 64),
        )
    )
    issued: list[Day2OpenFHEKeyPlanCapability] = []
    real_issue = plan_module._issue_from_day2_authority

    def record_issue(
        authority: authority_module.Day2CalibrationAuthority,
        content: bytes,
    ) -> Day2OpenFHEKeyPlanCapability:
        capability = real_issue(authority, content)
        issued.append(capability)
        return capability

    monkeypatch.setattr(
        plan_module,
        "repository_day2_calibration_authority",
        lambda: next(authorities),
    )
    monkeypatch.setattr(plan_module, "_issue_from_day2_authority", record_issue)

    with pytest.raises(Day2OpenFHEKeyPlanError, match="changed while issuing"):
        issue_repository_day2_openfhe_key_plan(plan_bytes)

    assert len(issued) == 1
    assert issued[0]._binding is None
