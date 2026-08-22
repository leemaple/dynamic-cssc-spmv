from __future__ import annotations

from copy import deepcopy
from dataclasses import MISSING, FrozenInstanceError, fields, replace
from typing import Any

import pytest

from dynamic_cssc.strong_reference_receipt import (
    StrongReferenceCapability,
    StrongReferenceReceiptError,
    _StrongReferenceTrustAnchor,
    _validate_against_anchor,
    validate_strong_reference_receipt,
)

SOURCE_GIT_SHA = "1" * 40
COMPILER_SHA256 = "2" * 64
VALIDATOR_SHA256 = "3" * 64


def _valid_receipt() -> dict[str, object]:
    return {
        "schema_version": "dynamic-cssc-strong-reference-receipt-v1",
        "status": "pass",
        "evidence_valid": True,
        "evidence_scope": ("actual-cssc-base-plus-strong-delta-whole-query-pinned-openfhe"),
        "builder_grammar_authorized": True,
        "source_git_sha": SOURCE_GIT_SHA,
        "witness_run_id": 999_000_111,
        "openfhe": {
            "version": "1.5.1",
            "commit": "1306d14f8c26bb6150d3e6ad54f28dfe1007689e",
        },
        "segment_width": 128,
        "provenance": {
            "compiler_sha256": COMPILER_SHA256,
            "validator_sha256": VALIDATOR_SHA256,
            "witness_source_sha256": "a" * 64,
            "witness_binary_sha256": "b" * 64,
            "binding_generator_sha256": "c" * 64,
        },
        "whole_query_fixture": {
            "kind": "actual-cssc-base-plus-strong-delta",
            "cloud_program_sha256": "4" * 64,
            "output_plan_sha256": "5" * 64,
            "execution_binding_sha256": "6" * 64,
        },
        "artifacts": {
            "witness_sha256": "7" * 64,
            "provenance_sha256": "8" * 64,
            "artifact_sha256": "9" * 64,
        },
        "property_contract_gate": {
            "schema_version": "dynamic-cssc-strong-reference-property-contract-gate-v1",
            "source_git_sha": SOURCE_GIT_SHA,
            "run_id": 999_000_222,
            "status": "pass",
            "compiler_sha256": COMPILER_SHA256,
            "validator_sha256": VALIDATOR_SHA256,
            "contract_test_source_sha256": "d" * 64,
            "junit_sha256": "e" * 64,
            "evidence_sha256": "f" * 64,
        },
        "coverage": {
            "base_plus_delta": True,
            "post_reduction_lanes": True,
            "f1m_random_and_dummy": True,
            "global_ci_above_slots": True,
            "tail": True,
            "boundary_127_128": True,
            "second_bfv_row_zero": True,
        },
        "claims": {
            "gate_eligible": False,
            "complete_cost_claim_allowed": False,
            "formal_parameter_claim_allowed": False,
            "end_to_end_correctness_claim_allowed": False,
            "security_claim_allowed": False,
            "formal_correctness_claim": False,
            "formal_security_claim": False,
            "formal_performance_claim": False,
            "mixed_workload_parameter_claim": False,
        },
    }


def _trust_anchor() -> _StrongReferenceTrustAnchor:
    return _StrongReferenceTrustAnchor(
        source_git_sha=SOURCE_GIT_SHA,
        witness_run_id=999_000_111,
        property_contract_run_id=999_000_222,
        compiler_sha256=COMPILER_SHA256,
        validator_sha256=VALIDATOR_SHA256,
        witness_source_sha256="a" * 64,
        witness_binary_sha256="b" * 64,
        binding_generator_sha256="c" * 64,
        cloud_program_sha256="4" * 64,
        output_plan_sha256="5" * 64,
        execution_binding_sha256="6" * 64,
        witness_sha256="7" * 64,
        provenance_sha256="8" * 64,
        artifact_sha256="9" * 64,
        contract_test_source_sha256="d" * 64,
        contract_junit_sha256="e" * 64,
        contract_evidence_sha256="f" * 64,
    )


def _validate_future_receipt(
    payload: object,
    trust_anchor: _StrongReferenceTrustAnchor | None = None,
) -> StrongReferenceCapability:
    return _validate_against_anchor(
        payload,
        trust_anchor=trust_anchor or _trust_anchor(),
    )


def test_public_admission_rejects_without_a_repository_approved_anchor() -> None:
    with pytest.raises(StrongReferenceReceiptError, match="repository-approved"):
        validate_strong_reference_receipt(_valid_receipt())


def test_private_parser_accepts_future_whole_query_receipt_against_selected_anchor() -> None:
    capability = _validate_future_receipt(_valid_receipt())

    assert {field.name: getattr(capability, field.name) for field in fields(capability)} == {
        "schema_version": "dynamic-cssc-strong-reference-receipt-v1",
        "evidence_scope": ("actual-cssc-base-plus-strong-delta-whole-query-pinned-openfhe"),
        "source_git_sha": SOURCE_GIT_SHA,
        "witness_run_id": 999_000_111,
        "builder_grammar_authorized": True,
        "openfhe_version": "1.5.1",
        "openfhe_commit": "1306d14f8c26bb6150d3e6ad54f28dfe1007689e",
        "segment_width": 128,
        "compiler_sha256": COMPILER_SHA256,
        "validator_sha256": VALIDATOR_SHA256,
        "witness_source_sha256": "a" * 64,
        "witness_binary_sha256": "b" * 64,
        "binding_generator_sha256": "c" * 64,
        "cloud_program_sha256": "4" * 64,
        "output_plan_sha256": "5" * 64,
        "execution_binding_sha256": "6" * 64,
        "witness_sha256": "7" * 64,
        "provenance_sha256": "8" * 64,
        "artifact_sha256": "9" * 64,
        "property_contract_run_id": 999_000_222,
        "contract_test_source_sha256": "d" * 64,
        "contract_junit_sha256": "e" * 64,
        "contract_evidence_sha256": "f" * 64,
    }


INVALID_FIELD_MUTATIONS = (
    ("schema_version", "dynamic-cssc-strong-reference-receipt-v2"),
    ("status", "failure"),
    ("evidence_valid", False),
    ("evidence_scope", "fixed-stride-primitive-correctness-only-pinned-openfhe"),
    ("builder_grammar_authorized", False),
    ("source_git_sha", "a" * 40),
    ("witness_run_id", 0),
    ("openfhe.version", "1.5.2"),
    ("openfhe.commit", "a" * 40),
    ("segment_width", 127),
    ("provenance.compiler_sha256", "a" * 64),
    ("provenance.validator_sha256", "b" * 64),
    ("provenance.witness_source_sha256", "0" * 64),
    ("provenance.witness_binary_sha256", "0" * 64),
    ("provenance.binding_generator_sha256", "0" * 64),
    ("whole_query_fixture.kind", "primitive-only"),
    ("whole_query_fixture.cloud_program_sha256", "0" * 64),
    ("whole_query_fixture.output_plan_sha256", "0" * 64),
    ("whole_query_fixture.execution_binding_sha256", "0" * 64),
    ("artifacts.witness_sha256", "0" * 64),
    ("artifacts.provenance_sha256", "0" * 64),
    ("artifacts.artifact_sha256", "0" * 64),
    (
        "property_contract_gate.schema_version",
        "dynamic-cssc-strong-reference-property-contract-gate-v2",
    ),
    ("property_contract_gate.source_git_sha", "a" * 40),
    ("property_contract_gate.run_id", 0),
    ("property_contract_gate.status", "failure"),
    ("property_contract_gate.compiler_sha256", "a" * 64),
    ("property_contract_gate.validator_sha256", "b" * 64),
    ("property_contract_gate.contract_test_source_sha256", "0" * 64),
    ("property_contract_gate.junit_sha256", "0" * 64),
    ("property_contract_gate.evidence_sha256", "0" * 64),
    ("coverage.base_plus_delta", False),
    ("coverage.post_reduction_lanes", False),
    ("coverage.f1m_random_and_dummy", False),
    ("coverage.global_ci_above_slots", False),
    ("coverage.tail", False),
    ("coverage.boundary_127_128", False),
    ("coverage.second_bfv_row_zero", False),
    ("claims.gate_eligible", True),
    ("claims.complete_cost_claim_allowed", True),
    ("claims.formal_parameter_claim_allowed", True),
    ("claims.end_to_end_correctness_claim_allowed", True),
    ("claims.security_claim_allowed", True),
    ("claims.formal_correctness_claim", True),
    ("claims.formal_security_claim", True),
    ("claims.formal_performance_claim", True),
    ("claims.mixed_workload_parameter_claim", True),
)


def _set_path(payload: dict[str, Any], path: str, value: object) -> None:
    fields = path.split(".")
    target = payload
    for field in fields[:-1]:
        target = target[field]
    target[fields[-1]] = value


@pytest.mark.parametrize(("path", "invalid_value"), INVALID_FIELD_MUTATIONS)
def test_every_receipt_field_fails_closed_under_invalid_mutation(
    path: str,
    invalid_value: object,
) -> None:
    payload = deepcopy(_valid_receipt())
    _set_path(payload, path, invalid_value)

    with pytest.raises(StrongReferenceReceiptError):
        _validate_future_receipt(payload)


@pytest.mark.parametrize(
    "object_path",
    (
        "",
        "openfhe",
        "provenance",
        "whole_query_fixture",
        "artifacts",
        "property_contract_gate",
        "coverage",
        "claims",
    ),
)
@pytest.mark.parametrize("mutation", ("missing", "unknown"))
def test_every_receipt_object_has_exact_closed_keys(
    object_path: str,
    mutation: str,
) -> None:
    payload = deepcopy(_valid_receipt())
    target = payload if not object_path else payload[object_path]
    assert isinstance(target, dict)
    if mutation == "missing":
        target.pop(next(iter(target)))
    else:
        target["unexpected"] = None

    with pytest.raises(StrongReferenceReceiptError, match="closed schema"):
        _validate_future_receipt(payload)


def test_successful_phase1_primitive_witness_is_not_admitted() -> None:
    phase1_witness = {
        "schema_version": "strong-packed-coo-witness-v1",
        "status": "pass",
        "evidence_scope": "fixed-stride-primitive-correctness-only-pinned-openfhe",
        "adapter": {"second_batching_row_zero": True},
        "bindings": {
            "cloud_program_digest": "1" * 64,
            "output_plan_digest": "2" * 64,
            "execution_binding_digest": "3" * 64,
        },
        "claims": {"gate_eligible": False},
    }
    assert phase1_witness["status"] == "pass"
    assert phase1_witness["evidence_scope"] == (
        "fixed-stride-primitive-correctness-only-pinned-openfhe"
    )

    with pytest.raises(StrongReferenceReceiptError, match="repository-approved"):
        validate_strong_reference_receipt(phase1_witness)
    with pytest.raises(StrongReferenceReceiptError, match="closed schema"):
        _validate_future_receipt(phase1_witness)


@pytest.mark.parametrize(
    ("path", "unauthorized_value"),
    (
        (
            "evidence_scope",
            "actual-cssc-base-plus-strong-delta-exact-fixture-correctness-pinned-openfhe",
        ),
        ("builder_grammar_authorized", False),
        ("property_contract_gate.status", "failure"),
        ("property_contract_gate.source_git_sha", "a" * 40),
        ("property_contract_gate.compiler_sha256", "a" * 64),
        ("property_contract_gate.validator_sha256", "b" * 64),
    ),
)
def test_fixture_correctness_and_coverage_are_not_sufficient_for_authorization(
    path: str,
    unauthorized_value: object,
) -> None:
    payload = deepcopy(_valid_receipt())
    _set_path(payload, path, unauthorized_value)
    coverage = payload["coverage"]
    assert isinstance(coverage, dict)
    assert all(coverage.values())

    with pytest.raises(StrongReferenceReceiptError):
        _validate_future_receipt(payload)


@pytest.mark.parametrize(
    "anchor_field",
    (
        "source_git_sha",
        "witness_run_id",
        "property_contract_run_id",
        "compiler_sha256",
        "validator_sha256",
        "witness_source_sha256",
        "witness_binary_sha256",
        "binding_generator_sha256",
        "cloud_program_sha256",
        "output_plan_sha256",
        "execution_binding_sha256",
        "witness_sha256",
        "provenance_sha256",
        "artifact_sha256",
        "contract_test_source_sha256",
        "contract_junit_sha256",
        "contract_evidence_sha256",
    ),
)
def test_receipt_must_match_every_independent_trust_anchor_field(
    anchor_field: str,
) -> None:
    anchor = _trust_anchor()
    current = getattr(anchor, anchor_field)
    if anchor_field == "source_git_sha":
        mismatch: object = "a" * 40
    elif isinstance(current, int):
        mismatch = current + 1
    else:
        mismatch = "0" * 64
    mismatched_anchor = replace(anchor, **{anchor_field: mismatch})

    with pytest.raises(StrongReferenceReceiptError):
        _validate_future_receipt(_valid_receipt(), mismatched_anchor)


@pytest.mark.parametrize(
    ("path", "invalid_value"),
    (
        ("witness_run_id", True),
        ("witness_run_id", float("nan")),
        ("segment_width", True),
        ("evidence_valid", 1),
        ("builder_grammar_authorized", 1),
        ("coverage.base_plus_delta", 1),
        ("claims.gate_eligible", 0),
        ("whole_query_fixture.cloud_program_sha256", float("inf")),
        ("property_contract_gate.run_id", float("nan")),
    ),
)
def test_receipt_rejects_type_coercions_and_nonfinite_values(
    path: str,
    invalid_value: object,
) -> None:
    payload = deepcopy(_valid_receipt())
    _set_path(payload, path, invalid_value)

    with pytest.raises(StrongReferenceReceiptError):
        _validate_future_receipt(payload)


@pytest.mark.parametrize(
    "path",
    (
        "provenance.compiler_sha256",
        "provenance.validator_sha256",
        "provenance.witness_source_sha256",
        "provenance.witness_binary_sha256",
        "provenance.binding_generator_sha256",
        "whole_query_fixture.cloud_program_sha256",
        "whole_query_fixture.output_plan_sha256",
        "whole_query_fixture.execution_binding_sha256",
        "artifacts.witness_sha256",
        "artifacts.provenance_sha256",
        "artifacts.artifact_sha256",
        "property_contract_gate.compiler_sha256",
        "property_contract_gate.validator_sha256",
        "property_contract_gate.contract_test_source_sha256",
        "property_contract_gate.junit_sha256",
        "property_contract_gate.evidence_sha256",
    ),
)
def test_every_receipt_sha256_must_be_lowercase(path: str) -> None:
    payload = deepcopy(_valid_receipt())
    _set_path(payload, path, "A" * 64)

    with pytest.raises(StrongReferenceReceiptError, match="lowercase SHA-256"):
        _validate_future_receipt(payload)


@pytest.mark.parametrize("claim", tuple(_valid_receipt()["claims"]))
def test_any_true_claim_is_rejected(claim: str) -> None:
    payload = deepcopy(_valid_receipt())
    claims = payload["claims"]
    assert isinstance(claims, dict)
    claims[claim] = True

    with pytest.raises(StrongReferenceReceiptError):
        _validate_future_receipt(payload)


def test_capability_is_immutable_and_narrow() -> None:
    capability = _validate_future_receipt(_valid_receipt())

    with pytest.raises(FrozenInstanceError):
        capability.segment_width = 127  # type: ignore[misc]
    assert not hasattr(capability, "__dict__")
    assert {field.name for field in fields(capability)} == {
        "schema_version",
        "evidence_scope",
        "source_git_sha",
        "witness_run_id",
        "builder_grammar_authorized",
        "openfhe_version",
        "openfhe_commit",
        "segment_width",
        "compiler_sha256",
        "validator_sha256",
        "witness_source_sha256",
        "witness_binary_sha256",
        "binding_generator_sha256",
        "cloud_program_sha256",
        "output_plan_sha256",
        "execution_binding_sha256",
        "witness_sha256",
        "provenance_sha256",
        "artifact_sha256",
        "property_contract_run_id",
        "contract_test_source_sha256",
        "contract_junit_sha256",
        "contract_evidence_sha256",
    }
    assert not hasattr(capability, "complete_reference_set")
    assert not hasattr(capability, "gate_eligible")


def test_capability_cannot_replace_receipt_and_trust_anchor_revalidation() -> None:
    with pytest.raises(TypeError, match="validate_strong_reference_receipt"):
        StrongReferenceCapability()

    capability = _validate_future_receipt(_valid_receipt())
    with pytest.raises(StrongReferenceReceiptError, match="repository-approved"):
        validate_strong_reference_receipt(capability)


def test_public_admission_does_not_accept_a_caller_supplied_anchor() -> None:
    with pytest.raises(TypeError, match="trust_anchor"):
        validate_strong_reference_receipt(  # type: ignore[call-arg]
            _valid_receipt(),
            trust_anchor=_trust_anchor(),
        )


def test_trust_anchor_is_immutable_and_has_no_defaults() -> None:
    anchor = _trust_anchor()

    with pytest.raises(FrozenInstanceError):
        anchor.witness_run_id = 1  # type: ignore[misc]
    assert not hasattr(anchor, "__dict__")
    assert all(
        field.default is MISSING and field.default_factory is MISSING for field in fields(anchor)
    )
