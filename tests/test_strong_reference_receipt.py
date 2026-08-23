from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from collections.abc import Iterator, Mapping
from copy import deepcopy
from dataclasses import FrozenInstanceError, fields
from inspect import signature
from pathlib import Path
from typing import Any

import pytest

import dynamic_cssc.strong_reference_receipt as receipt_module
from dynamic_cssc.strong_reference_receipt import (
    HistoricalStrongSourceAttestation,
    StrongReferenceCapability,
    StrongReferenceReceiptError,
    repository_historical_strong_source_attestation,
    repository_strong_reference_capability,
    validate_strong_reference_receipt,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ("git", *arguments),
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _strong_anchor_repository(
    tmp_path: Path,
    *,
    anchor_mode: int = 0o644,
    include_historical_source: bool = True,
) -> Path:
    repository = tmp_path / "strong-anchor-repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.email", "strong-anchor@example.invalid")
    _git(repository, "config", "user.name", "Strong Anchor Test")
    anchor = repository / "config/strong-reference-evidence-anchors.json"
    anchor.parent.mkdir(parents=True)
    shutil.copy2(REPOSITORY_ROOT / anchor.relative_to(repository), anchor)
    anchor.chmod(anchor_mode)
    _git(repository, "add", "--all")
    _git(repository, "commit", "-qm", "install strong descriptive anchor")
    if include_historical_source:
        _git(
            repository,
            "fetch",
            "-q",
            str(REPOSITORY_ROOT),
            "fcb00e0d7f111f3ab5003c111b124df83ae11813:refs/remotes/evidence/strong",
        )
    return repository


@pytest.fixture(scope="module", autouse=True)
def _repository_backed_strong_anchor(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[None]:
    """Keep zero-argument tests on a clean committed anchor, not the WIP checkout."""

    repository = _strong_anchor_repository(tmp_path_factory.mktemp("repository-strong-anchor"))
    original = receipt_module._REPOSITORY_ROOT
    receipt_module._REPOSITORY_ROOT = repository
    try:
        yield
    finally:
        receipt_module._REPOSITORY_ROOT = original


def _audited_receipt() -> dict[str, object]:
    """Independently audited receipt, copied as test data rather than from production."""

    return {
        "schema_version": "dynamic-cssc-strong-reference-receipt-v1",
        "status": "pass",
        "evidence_valid": True,
        "evidence_scope": "actual-cssc-base-plus-strong-delta-whole-query-pinned-openfhe",
        "builder_grammar_authorized": True,
        "source_git_sha": "fcb00e0d7f111f3ab5003c111b124df83ae11813",
        "witness_run_id": 32_581_653_504,
        "openfhe": {
            "version": "1.5.1",
            "commit": "1306d14f8c26bb6150d3e6ad54f28dfe1007689e",
        },
        "segment_width": 128,
        "provenance": {
            "compiler_sha256": ("8acff4d3805de05197468ef86d0f8567e7e1cc133abd1c65c99d4c35f3f8c142"),
            "validator_sha256": (
                "b77a10a78b06146b5efa829e789fd4a1d6055d7e84e275beda3297b5e8eb6cc2"
            ),
            "witness_source_sha256": (
                "354ec1e614b31e2e087b7de0d029240dba9f067b0298bf15393a474c8b3a0dfa"
            ),
            "witness_binary_sha256": (
                "0c803cdd44b0fd8b2e32c2d1dbd26c4d32f417f623abc816c1cabe4bae622329"
            ),
            "binding_generator_sha256": (
                "d8a5256b6f5a9d1ffec124ac5f4a06e8a9ff9f2290a75136a9cf7321d7c2152b"
            ),
        },
        "whole_query_fixture": {
            "kind": "actual-cssc-base-plus-strong-delta",
            "cloud_program_sha256": (
                "ac693f56e86bbf6fa807248f0601f1b91ef49d352a555804ba079695a0b0b549"
            ),
            "output_plan_sha256": (
                "516a957670bb1e61d465c69ffeb2df803222ecfee46892a0acb5ae11dab99345"
            ),
            "execution_binding_sha256": (
                "e23c13e451179cdde32a133172fc13f61abea701313a57a7522ddbab074ece96"
            ),
        },
        "artifacts": {
            "witness_sha256": ("55d95a2b8e7e4b0e07d4b13539fc3627b157c0bf33617ecf6f5cde2e189bb41d"),
            "provenance_sha256": (
                "c019a7646ddd9e886e55b012bef19deffddbedddb5f766e2209f29f86bbb4e3e"
            ),
            "artifact_sha256": ("c5f44b0c9475a66d49b48332e335cb58811cf4eec579ebff631123c4e4711afe"),
        },
        "property_contract_gate": {
            "schema_version": "dynamic-cssc-strong-reference-property-contract-gate-v1",
            "source_git_sha": "fcb00e0d7f111f3ab5003c111b124df83ae11813",
            "run_id": 32_581_653_504,
            "status": "pass",
            "compiler_sha256": ("8acff4d3805de05197468ef86d0f8567e7e1cc133abd1c65c99d4c35f3f8c142"),
            "validator_sha256": (
                "431d390b351182e2fae7f55698334f0dc99b6f557ffaa802ce94a0e51d0607c1"
            ),
            "contract_test_source_sha256": (
                "bcb0b3d69a629efc4cb8d76df33e4570712bdb6b2ea8f03ea55b0e5747a9266c"
            ),
            "junit_sha256": ("5ebf3a13b2d7c72c294d0e1727c4bf6f66ccea5386ce1960479d60b9f8760eb0"),
            "evidence_sha256": ("96d06122e07928011105a88e88493854645d99447c4d4390c8d9bcf0b784e214"),
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


EXPECTED_CAPABILITY = {
    "authority_state": "historical-descriptive-only",
    "schema_version": "dynamic-cssc-strong-reference-receipt-v1",
    "evidence_scope": "actual-cssc-base-plus-strong-delta-whole-query-pinned-openfhe",
    "source_git_sha": "fcb00e0d7f111f3ab5003c111b124df83ae11813",
    "witness_run_id": 32_581_653_504,
    "builder_grammar_authorized": True,
    "openfhe_version": "1.5.1",
    "openfhe_commit": "1306d14f8c26bb6150d3e6ad54f28dfe1007689e",
    "segment_width": 128,
    "compiler_sha256": "8acff4d3805de05197468ef86d0f8567e7e1cc133abd1c65c99d4c35f3f8c142",
    "whole_query_validator_sha256": (
        "b77a10a78b06146b5efa829e789fd4a1d6055d7e84e275beda3297b5e8eb6cc2"
    ),
    "property_contract_validator_sha256": (
        "431d390b351182e2fae7f55698334f0dc99b6f557ffaa802ce94a0e51d0607c1"
    ),
    "witness_source_sha256": ("354ec1e614b31e2e087b7de0d029240dba9f067b0298bf15393a474c8b3a0dfa"),
    "witness_binary_sha256": ("0c803cdd44b0fd8b2e32c2d1dbd26c4d32f417f623abc816c1cabe4bae622329"),
    "binding_generator_sha256": (
        "d8a5256b6f5a9d1ffec124ac5f4a06e8a9ff9f2290a75136a9cf7321d7c2152b"
    ),
    "cloud_program_sha256": ("ac693f56e86bbf6fa807248f0601f1b91ef49d352a555804ba079695a0b0b549"),
    "output_plan_sha256": "516a957670bb1e61d465c69ffeb2df803222ecfee46892a0acb5ae11dab99345",
    "execution_binding_sha256": (
        "e23c13e451179cdde32a133172fc13f61abea701313a57a7522ddbab074ece96"
    ),
    "witness_sha256": "55d95a2b8e7e4b0e07d4b13539fc3627b157c0bf33617ecf6f5cde2e189bb41d",
    "provenance_sha256": ("c019a7646ddd9e886e55b012bef19deffddbedddb5f766e2209f29f86bbb4e3e"),
    "artifact_sha256": "c5f44b0c9475a66d49b48332e335cb58811cf4eec579ebff631123c4e4711afe",
    "property_contract_run_id": 32_581_653_504,
    "contract_test_source_sha256": (
        "bcb0b3d69a629efc4cb8d76df33e4570712bdb6b2ea8f03ea55b0e5747a9266c"
    ),
    "contract_junit_sha256": ("5ebf3a13b2d7c72c294d0e1727c4bf6f66ccea5386ce1960479d60b9f8760eb0"),
    "contract_evidence_sha256": (
        "96d06122e07928011105a88e88493854645d99447c4d4390c8d9bcf0b784e214"
    ),
    "formal_authority_granted": False,
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
}


def _set_path(payload: dict[str, Any], path: str, value: object) -> None:
    path_fields = path.split(".")
    target = payload
    for field in path_fields[:-1]:
        target = target[field]
    target[path_fields[-1]] = value


def _forged_capability() -> StrongReferenceCapability:
    capability = object.__new__(StrongReferenceCapability)
    for field, value in EXPECTED_CAPABILITY.items():
        object.__setattr__(capability, field, value)
    return capability


def test_repository_admission_returns_independently_audited_capability() -> None:
    capability = repository_strong_reference_capability()

    assert {field.name: getattr(capability, field.name) for field in fields(capability)} == (
        EXPECTED_CAPABILITY
    )


def test_historical_anchor_is_canonical_data_and_capability_claims_remain_false() -> None:
    root = Path(__file__).resolve().parents[1]
    content = (root / "config/strong-reference-evidence-anchors.json").read_bytes()
    document = json.loads(content)
    assert content == (
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")
    anchor = document["anchors"][0]
    receipt = anchor["receipt"]
    receipt_bytes = (
        json.dumps(
            receipt,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")
    assert anchor["receipt_sha256"] == hashlib.sha256(receipt_bytes).hexdigest()
    assert anchor["artifact_sha256"] == receipt["artifacts"]["artifact_sha256"]
    assert anchor["source_behavior_set_schema_version"] == (
        "dynamic-cssc-historical-strong-correctness-behavior-set-v1"
    )
    assert anchor["source_behavior_set_sha256"] == (
        "11929722aaf1dbbe9d110b993780f33df1cfe9b6b2c31bbad81ccc694ff87234"
    )

    capability = repository_strong_reference_capability()
    assert capability.authority_state == "historical-descriptive-only"
    assert capability.formal_authority_granted is False
    assert all(getattr(capability, claim) is False for claim in receipt["claims"])


def test_repository_strong_anchor_must_be_a_git_100644_blob(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _strong_anchor_repository(tmp_path, anchor_mode=0o755)
    monkeypatch.setattr(receipt_module, "_REPOSITORY_ROOT", repository)

    with pytest.raises(StrongReferenceReceiptError, match="100644"):
        repository_strong_reference_capability()


def test_historical_strong_source_attestation_is_zero_argument_and_git_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _strong_anchor_repository(tmp_path)
    monkeypatch.setattr(receipt_module, "_REPOSITORY_ROOT", repository)

    attestation = repository_historical_strong_source_attestation()

    assert tuple(signature(repository_historical_strong_source_attestation).parameters) == ()
    assert type(attestation) is HistoricalStrongSourceAttestation
    assert attestation.source_git_sha == "fcb00e0d7f111f3ab5003c111b124df83ae11813"
    assert attestation.behavior_set_schema_version == (
        "dynamic-cssc-historical-strong-correctness-behavior-set-v1"
    )
    assert attestation.behavior_set_sha256 == (
        "11929722aaf1dbbe9d110b993780f33df1cfe9b6b2c31bbad81ccc694ff87234"
    )
    assert len(attestation.behavior_source_blob_sha256) == 30
    assert any(ref.endswith("/strong") for ref in attestation.reachable_ref_names)
    assert attestation.formal_authority_granted is False


def test_historical_strong_source_must_exist_and_be_reachable_from_a_ref(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _strong_anchor_repository(tmp_path, include_historical_source=False)
    monkeypatch.setattr(receipt_module, "_REPOSITORY_ROOT", repository)

    with pytest.raises(StrongReferenceReceiptError, match="historical.*commit|reachable"):
        repository_historical_strong_source_attestation()


def test_inline_anchor_or_receipt_monkeypatch_cannot_replace_repository_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        receipt_module,
        "_REPOSITORY_TRUST_ANCHORS",
        (object(),),
        raising=False,
    )
    forged_receipt = deepcopy(_audited_receipt())
    forged_receipt["artifacts"]["artifact_sha256"] = "0" * 64
    monkeypatch.setattr(
        receipt_module,
        "_repository_strong_reference_receipt",
        lambda: forged_receipt,
        raising=False,
    )

    capability = repository_strong_reference_capability()

    assert capability.artifact_sha256 == EXPECTED_CAPABILITY["artifact_sha256"]


def test_repository_projection_has_no_mutable_module_policy() -> None:
    policy = getattr(receipt_module, "_CAPABILITY_POLICY", None)
    if isinstance(policy, dict):
        original = policy["builder_grammar_authorized"]
        try:
            policy["builder_grammar_authorized"] = False
            capability = repository_strong_reference_capability()
        finally:
            policy["builder_grammar_authorized"] = original
    else:
        capability = repository_strong_reference_capability()

    assert policy is None
    assert capability.builder_grammar_authorized is True


@pytest.mark.parametrize("helper_name", ("_admit_capability", "_validate_against_anchor"))
def test_module_exposes_no_caller_anchor_projection_helper(helper_name: str) -> None:
    assert not hasattr(receipt_module, helper_name)


def test_receipt_schema_is_recursively_immutable_against_in_place_mutation() -> None:
    schema = receipt_module._RECEIPT_V1_SCHEMA
    claims = schema["claims"]
    assert isinstance(schema, Mapping)
    assert isinstance(claims, Mapping)

    original_security_claim = claims["security_claim_allowed"]
    try:
        with pytest.raises(TypeError):
            claims["security_claim_allowed"] = True  # type: ignore[index]
    finally:
        if isinstance(claims, dict):
            claims["security_claim_allowed"] = original_security_claim

    original_claims = schema["claims"]
    try:
        with pytest.raises(TypeError):
            schema["claims"] = {}  # type: ignore[index]
    finally:
        if isinstance(schema, dict):
            schema["claims"] = original_claims

    assert repository_strong_reference_capability().builder_grammar_authorized is True


def test_public_validation_accepts_the_independently_audited_receipt() -> None:
    assert validate_strong_reference_receipt(_audited_receipt()) == (
        repository_strong_reference_capability()
    )


def test_repository_admission_does_not_accept_a_caller_supplied_capability() -> None:
    capability = validate_strong_reference_receipt(_audited_receipt())

    with pytest.raises(StrongReferenceReceiptError, match="repository-approved"):
        validate_strong_reference_receipt(capability)
    with pytest.raises(TypeError):
        repository_strong_reference_capability(capability)  # type: ignore[call-arg]


def test_forged_descriptive_projection_cannot_be_used_as_any_admission_input() -> None:
    capability = _forged_capability()
    assert capability == repository_strong_reference_capability()

    with pytest.raises(StrongReferenceReceiptError, match="repository-approved"):
        validate_strong_reference_receipt(capability)
    with pytest.raises(TypeError):
        repository_strong_reference_capability(capability)  # type: ignore[call-arg]


def test_public_validation_does_not_accept_a_caller_supplied_anchor() -> None:
    with pytest.raises(TypeError, match="trust_anchor"):
        validate_strong_reference_receipt(  # type: ignore[call-arg]
            _audited_receipt(),
            trust_anchor=object(),
        )


def test_normal_construction_is_disabled_for_the_immutable_descriptive_projection() -> None:
    with pytest.raises(TypeError, match="conventional .* construction is disabled"):
        StrongReferenceCapability()

    capability = repository_strong_reference_capability()
    with pytest.raises(FrozenInstanceError):
        capability.segment_width = 127  # type: ignore[misc]

    assert not hasattr(capability, "__dict__")
    assert {field.name for field in fields(capability)} == set(EXPECTED_CAPABILITY)
    assert not hasattr(capability, "validator_sha256")
    assert capability.authority_state == "historical-descriptive-only"
    assert capability.formal_authority_granted is False
    assert capability.candidate_registration_allowed is False
    assert capability.complete_reference_set is False
    assert capability.gate_eligible is False
    assert capability.complete_cost_claim_allowed is False
    assert capability.end_to_end_correctness_claim_allowed is False
    assert capability.security_claim_allowed is False
    assert capability.formal_performance_claim is False


INVALID_FIELD_MUTATIONS = (
    ("schema_version", "dynamic-cssc-strong-reference-receipt-v2"),
    ("status", "failure"),
    ("evidence_valid", False),
    ("evidence_scope", "fixed-stride-primitive-correctness-only-pinned-openfhe"),
    ("builder_grammar_authorized", False),
    ("source_git_sha", "a" * 40),
    ("witness_run_id", 32_581_653_505),
    ("openfhe.version", "1.5.2"),
    ("openfhe.commit", "a" * 40),
    ("segment_width", 127),
    ("provenance.compiler_sha256", "0" * 64),
    ("provenance.validator_sha256", "0" * 64),
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
    ("property_contract_gate.run_id", 32_581_653_505),
    ("property_contract_gate.status", "failure"),
    ("property_contract_gate.compiler_sha256", "0" * 64),
    ("property_contract_gate.validator_sha256", "0" * 64),
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
)


@pytest.mark.parametrize(("path", "invalid_value"), INVALID_FIELD_MUTATIONS)
def test_every_receipt_field_fails_closed_under_invalid_mutation(
    path: str,
    invalid_value: object,
) -> None:
    payload = deepcopy(_audited_receipt())
    _set_path(payload, path, invalid_value)

    with pytest.raises(StrongReferenceReceiptError):
        validate_strong_reference_receipt(payload)


def test_whole_query_and_property_validator_identities_cannot_be_interchanged() -> None:
    payload = deepcopy(_audited_receipt())
    provenance = payload["provenance"]
    property_gate = payload["property_contract_gate"]
    assert isinstance(provenance, dict)
    assert isinstance(property_gate, dict)
    provenance["validator_sha256"], property_gate["validator_sha256"] = (
        property_gate["validator_sha256"],
        provenance["validator_sha256"],
    )

    with pytest.raises(StrongReferenceReceiptError):
        validate_strong_reference_receipt(payload)


def test_legacy_ambiguous_validator_field_is_rejected_by_the_closed_schema() -> None:
    payload = deepcopy(_audited_receipt())
    payload["validator_sha256"] = "b77a10a78b06146b5efa829e789fd4a1d6055d7e84e275beda3297b5e8eb6cc2"

    with pytest.raises(StrongReferenceReceiptError, match="repository-approved"):
        validate_strong_reference_receipt(payload)


CLAIM_FIELDS = (
    "gate_eligible",
    "candidate_registered",
    "candidate_registration_allowed",
    "complete_reference_set",
    "complete_cost_claim_allowed",
    "formal_parameter_claim_allowed",
    "end_to_end_correctness_claim_allowed",
    "security_claim_allowed",
    "formal_correctness_claim",
    "formal_security_claim",
    "formal_performance_claim",
    "mixed_workload_parameter_claim",
)


@pytest.mark.parametrize("claim", CLAIM_FIELDS)
def test_no_complete_reference_cost_security_performance_or_end_to_end_claim_is_admitted(
    claim: str,
) -> None:
    payload = deepcopy(_audited_receipt())
    claims = payload["claims"]
    assert isinstance(claims, dict)
    assert not any(claims.values())
    claims[claim] = True

    with pytest.raises(StrongReferenceReceiptError):
        validate_strong_reference_receipt(payload)


@pytest.mark.parametrize("claim", CLAIM_FIELDS)
def test_every_real_artifact_claim_is_required(claim: str) -> None:
    payload = deepcopy(_audited_receipt())
    claims = payload["claims"]
    assert isinstance(claims, dict)
    claims.pop(claim)

    with pytest.raises(StrongReferenceReceiptError, match="repository-approved"):
        validate_strong_reference_receipt(payload)


def test_unknown_claim_is_rejected_even_when_false() -> None:
    payload = deepcopy(_audited_receipt())
    claims = payload["claims"]
    assert isinstance(claims, dict)
    claims["candidate_authority_granted"] = False

    with pytest.raises(StrongReferenceReceiptError, match="repository-approved"):
        validate_strong_reference_receipt(payload)


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
    payload = deepcopy(_audited_receipt())
    target = payload if not object_path else payload[object_path]
    assert isinstance(target, dict)
    if mutation == "missing":
        target.pop(next(iter(target)))
    else:
        target["unexpected"] = None

    with pytest.raises(StrongReferenceReceiptError, match="repository-approved"):
        validate_strong_reference_receipt(payload)


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
    payload = deepcopy(_audited_receipt())
    _set_path(payload, path, invalid_value)

    with pytest.raises(StrongReferenceReceiptError):
        validate_strong_reference_receipt(payload)


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
    payload = deepcopy(_audited_receipt())
    _set_path(payload, path, "A" * 64)

    with pytest.raises(StrongReferenceReceiptError):
        validate_strong_reference_receipt(payload)


def test_structurally_valid_but_unanchored_receipt_is_rejected() -> None:
    payload = deepcopy(_audited_receipt())
    payload["source_git_sha"] = "a" * 40
    property_gate = payload["property_contract_gate"]
    assert isinstance(property_gate, dict)
    property_gate["source_git_sha"] = "a" * 40

    with pytest.raises(StrongReferenceReceiptError, match="repository-approved"):
        validate_strong_reference_receipt(payload)


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

    with pytest.raises(StrongReferenceReceiptError, match="repository-approved"):
        validate_strong_reference_receipt(phase1_witness)
