from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, fields
from pathlib import Path
from types import MappingProxyType

from .evidence_compatibility import (
    STRONG_REFERENCE_EVIDENCE_ANCHOR_PATH,
    EvidenceCompatibilityError,
    EvidenceRole,
    HistoricalStrongSourceAttestation,
    _verify_historical_strong_source,
    read_current_role_evidence_data,
)

__all__ = (
    "HistoricalStrongSourceAttestation",
    "StrongReferenceCapability",
    "StrongReferenceReceiptError",
    "repository_historical_strong_source_attestation",
    "repository_strong_reference_capability",
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
    """Raised when a receipt cannot produce a repository-anchored projection."""


@dataclass(frozen=True, slots=True)
class _StrongReferenceTrustAnchor:
    """Independent expected identities for one admissible evidence bundle."""

    source_git_sha: str
    witness_run_id: int
    property_contract_run_id: int
    compiler_sha256: str
    whole_query_validator_sha256: str
    property_contract_validator_sha256: str
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
    """Immutable descriptive projection of one pinned evidence receipt.

    The disabled constructor covers conventional construction only; Python callers can
    forge equivalent values through reflection. The value is therefore never authority.
    A future registry must use the zero-argument repository admission seam itself.
    """

    authority_state: str
    schema_version: str
    evidence_scope: str
    source_git_sha: str
    witness_run_id: int
    builder_grammar_authorized: bool
    openfhe_version: str
    openfhe_commit: str
    segment_width: int
    compiler_sha256: str
    whole_query_validator_sha256: str
    property_contract_validator_sha256: str
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
    formal_authority_granted: bool
    gate_eligible: bool
    candidate_registered: bool
    candidate_registration_allowed: bool
    complete_reference_set: bool
    complete_cost_claim_allowed: bool
    formal_parameter_claim_allowed: bool
    end_to_end_correctness_claim_allowed: bool
    security_claim_allowed: bool
    formal_correctness_claim: bool
    formal_security_claim: bool
    formal_performance_claim: bool
    mixed_workload_parameter_claim: bool

    def __init__(self) -> None:
        raise TypeError(
            "conventional StrongReferenceCapability construction is disabled; "
            "validate a receipt for a descriptive projection"
        )


@dataclass(frozen=True, slots=True)
class _Anchored:
    field: str


def _anchor(field: str) -> _Anchored:
    return _Anchored(field)


def _freeze_schema(schema: dict[str, object]) -> Mapping[str, object]:
    return MappingProxyType(
        {
            field: _freeze_schema(expected) if isinstance(expected, dict) else expected
            for field, expected in schema.items()
        }
    )


_RECEIPT_V1_SCHEMA: Mapping[str, object] = _freeze_schema(
    {
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
            "validator_sha256": _anchor("whole_query_validator_sha256"),
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
            "validator_sha256": _anchor("property_contract_validator_sha256"),
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
            "candidate_registered": False,
            "candidate_registration_allowed": False,
            "complete_reference_set": False,
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
)


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
    if isinstance(schema, Mapping):
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


_ANCHOR_SET_SCHEMA_VERSION = "dynamic-cssc-strong-reference-evidence-anchor-set-v1"
_ANCHOR_SCHEMA_VERSION = "dynamic-cssc-strong-reference-evidence-anchor-v1"
_ANCHOR_AUTHORITY_STATE = "historical-descriptive-only"
_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _canonical_json_bytes(payload: object) -> bytes:
    try:
        rendered = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise StrongReferenceReceiptError("strong reference evidence is not JSON") from error
    return (rendered + "\n").encode("ascii")


def _read_anchor_bytes() -> bytes:
    try:
        blobs = read_current_role_evidence_data(
            EvidenceRole.STRONG_CORRECTNESS,
            _REPOSITORY_ROOT,
        )
    except EvidenceCompatibilityError as error:
        raise StrongReferenceReceiptError(
            f"repository strong-reference evidence anchor is unavailable: {error}"
        ) from error
    if len(blobs) != 1 or blobs[0].path != STRONG_REFERENCE_EVIDENCE_ANCHOR_PATH:
        raise StrongReferenceReceiptError(
            "repository strong-reference evidence anchor path set is not exact"
        )
    return blobs[0].content


def _decode_anchor_data(content: bytes) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        decoded: dict[str, object] = {}
        for key, value in pairs:
            if key in decoded:
                raise StrongReferenceReceiptError(
                    "repository strong-reference evidence contains duplicate JSON keys"
                )
            decoded[key] = value
        return decoded

    try:
        document = json.loads(
            content.decode("ascii"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                StrongReferenceReceiptError(
                    f"repository strong-reference evidence contains {value}"
                )
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StrongReferenceReceiptError(
            "repository strong-reference evidence is not canonical JSON"
        ) from error
    if type(document) is not dict or _canonical_json_bytes(document) != content:
        raise StrongReferenceReceiptError(
            "repository strong-reference evidence is not canonical JSON"
        )
    return document


def _trust_anchor_from_receipt(receipt: dict[str, object]) -> _StrongReferenceTrustAnchor:
    try:
        provenance = receipt["provenance"]
        fixture = receipt["whole_query_fixture"]
        artifacts = receipt["artifacts"]
        contract = receipt["property_contract_gate"]
        if not all(type(value) is dict for value in (provenance, fixture, artifacts, contract)):
            raise TypeError
        return _StrongReferenceTrustAnchor(
            source_git_sha=receipt["source_git_sha"],  # type: ignore[arg-type]
            witness_run_id=receipt["witness_run_id"],  # type: ignore[arg-type]
            property_contract_run_id=contract["run_id"],  # type: ignore[index,arg-type]
            compiler_sha256=provenance["compiler_sha256"],  # type: ignore[index,arg-type]
            whole_query_validator_sha256=provenance["validator_sha256"],  # type: ignore[index,arg-type]
            property_contract_validator_sha256=contract["validator_sha256"],  # type: ignore[index,arg-type]
            witness_source_sha256=provenance["witness_source_sha256"],  # type: ignore[index,arg-type]
            witness_binary_sha256=provenance["witness_binary_sha256"],  # type: ignore[index,arg-type]
            binding_generator_sha256=provenance["binding_generator_sha256"],  # type: ignore[index,arg-type]
            cloud_program_sha256=fixture["cloud_program_sha256"],  # type: ignore[index,arg-type]
            output_plan_sha256=fixture["output_plan_sha256"],  # type: ignore[index,arg-type]
            execution_binding_sha256=fixture["execution_binding_sha256"],  # type: ignore[index,arg-type]
            witness_sha256=artifacts["witness_sha256"],  # type: ignore[index,arg-type]
            provenance_sha256=artifacts["provenance_sha256"],  # type: ignore[index,arg-type]
            artifact_sha256=artifacts["artifact_sha256"],  # type: ignore[index,arg-type]
            contract_test_source_sha256=contract["contract_test_source_sha256"],  # type: ignore[index,arg-type]
            contract_junit_sha256=contract["junit_sha256"],  # type: ignore[index,arg-type]
            contract_evidence_sha256=contract["evidence_sha256"],  # type: ignore[index,arg-type]
        )
    except (KeyError, TypeError) as error:
        raise StrongReferenceReceiptError(
            "repository strong-reference receipt cannot define its closed trust anchor"
        ) from error


def _repository_anchor() -> tuple[
    dict[str, object],
    _StrongReferenceTrustAnchor,
    dict[str, object],
]:
    document = _decode_anchor_data(_read_anchor_bytes())
    if set(document) != {"anchors", "schema_version"}:
        raise StrongReferenceReceiptError(
            "repository strong-reference anchor-set keys must be exact"
        )
    if document["schema_version"] != _ANCHOR_SET_SCHEMA_VERSION:
        raise StrongReferenceReceiptError(
            "repository strong-reference anchor-set schema is not frozen"
        )
    anchors = document["anchors"]
    if type(anchors) is not list or len(anchors) != 1 or type(anchors[0]) is not dict:
        raise StrongReferenceReceiptError(
            "repository strong-reference anchor set must contain exactly one historical record"
        )
    anchor = anchors[0]
    if set(anchor) != {
        "artifact_sha256",
        "authority_state",
        "receipt",
        "receipt_sha256",
        "role",
        "schema_version",
        "source_behavior_set_schema_version",
        "source_behavior_set_sha256",
    }:
        raise StrongReferenceReceiptError("repository strong-reference anchor keys must be exact")
    if (
        anchor["schema_version"] != _ANCHOR_SCHEMA_VERSION
        or anchor["role"] != "strong-correctness"
        or anchor["authority_state"] != _ANCHOR_AUTHORITY_STATE
    ):
        raise StrongReferenceReceiptError(
            "repository strong-reference historical authority state is not frozen"
        )
    receipt = anchor["receipt"]
    if type(receipt) is not dict:
        raise StrongReferenceReceiptError("repository strong-reference receipt must be an object")
    receipt_sha256 = hashlib.sha256(_canonical_json_bytes(receipt)).hexdigest()
    if anchor["receipt_sha256"] != receipt_sha256:
        raise StrongReferenceReceiptError(
            "repository strong-reference receipt digest does not match its canonical bytes"
        )
    artifacts = receipt.get("artifacts")
    if type(artifacts) is not dict or anchor["artifact_sha256"] != artifacts.get("artifact_sha256"):
        raise StrongReferenceReceiptError(
            "repository strong-reference artifact identity is not closed"
        )
    trust_anchor = _validate_trust_anchor(_trust_anchor_from_receipt(receipt))
    _validate_closed_schema(receipt, _RECEIPT_V1_SCHEMA, "receipt", trust_anchor)
    return receipt, trust_anchor, anchor


def validate_strong_reference_receipt(payload: object) -> StrongReferenceCapability:
    """Validate a receipt and return its descriptive repository-anchored projection."""

    _repository_receipt, trust_anchor, _anchor_document = _repository_anchor()
    try:
        _validate_closed_schema(payload, _RECEIPT_V1_SCHEMA, "receipt", trust_anchor)
    except StrongReferenceReceiptError as error:
        raise StrongReferenceReceiptError(
            "receipt does not match the repository-approved strong-reference data anchor"
        ) from error
    capability = object.__new__(StrongReferenceCapability)
    projection = (
        ("authority_state", _ANCHOR_AUTHORITY_STATE),
        ("schema_version", RECEIPT_SCHEMA_VERSION),
        ("evidence_scope", WHOLE_QUERY_EVIDENCE_SCOPE),
        ("source_git_sha", trust_anchor.source_git_sha),
        ("witness_run_id", trust_anchor.witness_run_id),
        ("builder_grammar_authorized", True),
        ("openfhe_version", PINNED_OPENFHE_VERSION),
        ("openfhe_commit", PINNED_OPENFHE_COMMIT),
        ("segment_width", FROZEN_SEGMENT_WIDTH),
        ("compiler_sha256", trust_anchor.compiler_sha256),
        ("whole_query_validator_sha256", trust_anchor.whole_query_validator_sha256),
        (
            "property_contract_validator_sha256",
            trust_anchor.property_contract_validator_sha256,
        ),
        ("witness_source_sha256", trust_anchor.witness_source_sha256),
        ("witness_binary_sha256", trust_anchor.witness_binary_sha256),
        ("binding_generator_sha256", trust_anchor.binding_generator_sha256),
        ("cloud_program_sha256", trust_anchor.cloud_program_sha256),
        ("output_plan_sha256", trust_anchor.output_plan_sha256),
        ("execution_binding_sha256", trust_anchor.execution_binding_sha256),
        ("witness_sha256", trust_anchor.witness_sha256),
        ("provenance_sha256", trust_anchor.provenance_sha256),
        ("artifact_sha256", trust_anchor.artifact_sha256),
        ("property_contract_run_id", trust_anchor.property_contract_run_id),
        ("contract_test_source_sha256", trust_anchor.contract_test_source_sha256),
        ("contract_junit_sha256", trust_anchor.contract_junit_sha256),
        ("contract_evidence_sha256", trust_anchor.contract_evidence_sha256),
        ("formal_authority_granted", False),
        ("gate_eligible", False),
        ("candidate_registered", False),
        ("candidate_registration_allowed", False),
        ("complete_reference_set", False),
        ("complete_cost_claim_allowed", False),
        ("formal_parameter_claim_allowed", False),
        ("end_to_end_correctness_claim_allowed", False),
        ("security_claim_allowed", False),
        ("formal_correctness_claim", False),
        ("formal_security_claim", False),
        ("formal_performance_claim", False),
        ("mixed_workload_parameter_claim", False),
    )
    for field, value in projection:
        object.__setattr__(capability, field, value)
    return capability


def repository_strong_reference_capability() -> StrongReferenceCapability:
    """Return the historical receipt identity as a non-authoritative projection."""

    receipt, _trust_anchor, _anchor_document = _repository_anchor()
    return validate_strong_reference_receipt(receipt)


def repository_historical_strong_source_attestation() -> HistoricalStrongSourceAttestation:
    """Verify the repository-anchored historical STRONG source without caller input."""

    _receipt, trust_anchor, anchor = _repository_anchor()
    try:
        return _verify_historical_strong_source(
            _REPOSITORY_ROOT,
            source_git_sha=trust_anchor.source_git_sha,
            expected_behavior_set_schema_version=anchor["source_behavior_set_schema_version"],
            expected_behavior_set_sha256=anchor["source_behavior_set_sha256"],
        )
    except EvidenceCompatibilityError as error:
        raise StrongReferenceReceiptError(
            f"repository historical strong source commit attestation failed: {error}"
        ) from error
