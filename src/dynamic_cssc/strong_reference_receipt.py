from __future__ import annotations

import re
from dataclasses import dataclass, fields

__all__ = (
    "StrongReferenceCapability",
    "StrongReferenceReceiptError",
    "validate_strong_reference_receipt",
)

RECEIPT_SCHEMA_VERSION = "dynamic-cssc-strong-reference-receipt-v1"
WHOLE_QUERY_EVIDENCE_SCOPE = "actual-cssc-base-plus-strong-delta-whole-query-pinned-openfhe"
WHOLE_QUERY_FIXTURE_KIND = "actual-cssc-base-plus-strong-delta"
PROPERTY_CONTRACT_GATE_SCHEMA_VERSION = "dynamic-cssc-strong-reference-property-contract-gate-v1"
PINNED_OPENFHE_VERSION = "1.5.1"
PINNED_OPENFHE_COMMIT = "1306d14f8c26bb6150d3e6ad54f28dfe1007689e"
FROZEN_SEGMENT_WIDTH = 128

_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")


class StrongReferenceReceiptError(ValueError):
    """Raised when a receipt cannot authorize a strong-reference capability."""


@dataclass(frozen=True, slots=True)
class _StrongReferenceTrustAnchor:
    """Independent expected identities for one admissible evidence bundle."""

    source_git_sha: str
    witness_run_id: int
    property_contract_run_id: int
    compiler_sha256: str
    validator_sha256: str
    witness_source_sha256: str
    witness_binary_sha256: str
    binding_generator_sha256: str
    cloud_program_sha256: str
    output_plan_sha256: str
    execution_binding_sha256: str
    witness_sha256: str
    provenance_sha256: str
    artifact_sha256: str
    contract_test_source_sha256: str
    contract_junit_sha256: str
    contract_evidence_sha256: str


@dataclass(frozen=True, slots=True, init=False)
class StrongReferenceCapability:
    """Identifiers admitted from one pinned whole-query evidence receipt.

    The disabled constructor is API hardening, not cryptographic sealing. A future
    registry must call public admission against the repository-owned trust-anchor
    allowlist at load time; it must not accept a caller-supplied capability as authority.
    """

    schema_version: str
    evidence_scope: str
    source_git_sha: str
    witness_run_id: int
    builder_grammar_authorized: bool
    openfhe_version: str
    openfhe_commit: str
    segment_width: int
    compiler_sha256: str
    validator_sha256: str
    witness_source_sha256: str
    witness_binary_sha256: str
    binding_generator_sha256: str
    cloud_program_sha256: str
    output_plan_sha256: str
    execution_binding_sha256: str
    witness_sha256: str
    provenance_sha256: str
    artifact_sha256: str
    property_contract_run_id: int
    contract_test_source_sha256: str
    contract_junit_sha256: str
    contract_evidence_sha256: str

    def __init__(self) -> None:
        raise TypeError(
            "StrongReferenceCapability is produced only by validate_strong_reference_receipt"
        )


@dataclass(frozen=True, slots=True)
class _Anchored:
    field: str


def _anchor(field: str) -> _Anchored:
    return _Anchored(field)


_RECEIPT_V1_SCHEMA: dict[str, object] = {
    "schema_version": RECEIPT_SCHEMA_VERSION,
    "status": "pass",
    "evidence_valid": True,
    "evidence_scope": WHOLE_QUERY_EVIDENCE_SCOPE,
    "builder_grammar_authorized": True,
    "source_git_sha": _anchor("source_git_sha"),
    "witness_run_id": _anchor("witness_run_id"),
    "openfhe": {
        "version": PINNED_OPENFHE_VERSION,
        "commit": PINNED_OPENFHE_COMMIT,
    },
    "segment_width": FROZEN_SEGMENT_WIDTH,
    "provenance": {
        "compiler_sha256": _anchor("compiler_sha256"),
        "validator_sha256": _anchor("validator_sha256"),
        "witness_source_sha256": _anchor("witness_source_sha256"),
        "witness_binary_sha256": _anchor("witness_binary_sha256"),
        "binding_generator_sha256": _anchor("binding_generator_sha256"),
    },
    "whole_query_fixture": {
        "kind": WHOLE_QUERY_FIXTURE_KIND,
        "cloud_program_sha256": _anchor("cloud_program_sha256"),
        "output_plan_sha256": _anchor("output_plan_sha256"),
        "execution_binding_sha256": _anchor("execution_binding_sha256"),
    },
    "artifacts": {
        "witness_sha256": _anchor("witness_sha256"),
        "provenance_sha256": _anchor("provenance_sha256"),
        "artifact_sha256": _anchor("artifact_sha256"),
    },
    "property_contract_gate": {
        "schema_version": PROPERTY_CONTRACT_GATE_SCHEMA_VERSION,
        "source_git_sha": _anchor("source_git_sha"),
        "run_id": _anchor("property_contract_run_id"),
        "status": "pass",
        "compiler_sha256": _anchor("compiler_sha256"),
        "validator_sha256": _anchor("validator_sha256"),
        "contract_test_source_sha256": _anchor("contract_test_source_sha256"),
        "junit_sha256": _anchor("contract_junit_sha256"),
        "evidence_sha256": _anchor("contract_evidence_sha256"),
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

_CAPABILITY_POLICY: dict[str, object] = {
    "schema_version": RECEIPT_SCHEMA_VERSION,
    "evidence_scope": WHOLE_QUERY_EVIDENCE_SCOPE,
    "builder_grammar_authorized": True,
    "openfhe_version": PINNED_OPENFHE_VERSION,
    "openfhe_commit": PINNED_OPENFHE_COMMIT,
    "segment_width": FROZEN_SEGMENT_WIDTH,
}


def _closed_object(value: object, fields: set[str], context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise StrongReferenceReceiptError(f"{context} must be an object")
    if set(value) != fields:
        raise StrongReferenceReceiptError(f"{context} keys must exactly match the closed schema")
    return value


def _require_exact(value: object, expected: object, context: str) -> None:
    if type(value) is not type(expected) or value != expected:
        raise StrongReferenceReceiptError(f"{context} must equal {expected!r}")


def _require_lower_sha256(value: object, context: str) -> str:
    if not isinstance(value, str) or _LOWER_SHA256.fullmatch(value) is None:
        raise StrongReferenceReceiptError(f"{context} must be a lowercase SHA-256")
    return value


def _require_lower_git_sha(value: object, context: str) -> str:
    if not isinstance(value, str) or _LOWER_GIT_SHA.fullmatch(value) is None:
        raise StrongReferenceReceiptError(f"{context} must be a full lowercase Git SHA")
    return value


def _require_positive_run_id(value: object, context: str) -> int:
    if type(value) is not int or value <= 0:
        raise StrongReferenceReceiptError(f"{context} must be a positive strict integer")
    return value


def _validate_trust_anchor(value: object) -> _StrongReferenceTrustAnchor:
    if type(value) is not _StrongReferenceTrustAnchor:
        raise StrongReferenceReceiptError(
            "trust_anchor must be an immutable repository trust anchor"
        )
    _require_lower_git_sha(value.source_git_sha, "trust_anchor.source_git_sha")
    _require_positive_run_id(value.witness_run_id, "trust_anchor.witness_run_id")
    _require_positive_run_id(
        value.property_contract_run_id,
        "trust_anchor.property_contract_run_id",
    )
    for field in fields(value):
        if field.name.endswith("sha256"):
            _require_lower_sha256(
                getattr(value, field.name),
                f"trust_anchor.{field.name}",
            )
    return value


def _validate_anchored_field(
    value: object,
    anchored: _Anchored,
    context: str,
    trust_anchor: _StrongReferenceTrustAnchor,
) -> None:
    if anchored.field == "source_git_sha":
        _require_lower_git_sha(value, context)
    elif anchored.field.endswith("run_id"):
        _require_positive_run_id(value, context)
    else:
        _require_lower_sha256(value, context)
    _require_exact(value, getattr(trust_anchor, anchored.field), context)


def _validate_closed_schema(
    value: object,
    schema: object,
    context: str,
    trust_anchor: _StrongReferenceTrustAnchor,
) -> None:
    if isinstance(schema, _Anchored):
        _validate_anchored_field(value, schema, context, trust_anchor)
        return
    if isinstance(schema, dict):
        actual = _closed_object(value, set(schema), context)
        for field, expected in schema.items():
            _validate_closed_schema(
                actual[field],
                expected,
                f"{context}.{field}",
                trust_anchor,
            )
        return
    _require_exact(value, schema, context)


def _admit_capability(
    trust_anchor: _StrongReferenceTrustAnchor,
) -> StrongReferenceCapability:
    capability = object.__new__(StrongReferenceCapability)
    for field in fields(capability):
        value = _CAPABILITY_POLICY.get(
            field.name,
            getattr(trust_anchor, field.name, None),
        )
        object.__setattr__(capability, field.name, value)
    return capability


def _validate_against_anchor(
    payload: object,
    *,
    trust_anchor: _StrongReferenceTrustAnchor,
) -> StrongReferenceCapability:
    """Validate a receipt against one already-selected repository trust anchor."""

    trust_anchor = _validate_trust_anchor(trust_anchor)
    _validate_closed_schema(payload, _RECEIPT_V1_SCHEMA, "receipt", trust_anchor)
    return _admit_capability(trust_anchor)


_REPOSITORY_TRUST_ANCHORS: tuple[_StrongReferenceTrustAnchor, ...] = ()


def validate_strong_reference_receipt(payload: object) -> StrongReferenceCapability:
    """Admit a receipt only through the repository-owned trust-anchor allowlist."""

    for trust_anchor in _REPOSITORY_TRUST_ANCHORS:
        try:
            return _validate_against_anchor(payload, trust_anchor=trust_anchor)
        except StrongReferenceReceiptError:
            continue
    raise StrongReferenceReceiptError(
        "receipt does not match any repository-approved strong-reference trust anchor"
    )
