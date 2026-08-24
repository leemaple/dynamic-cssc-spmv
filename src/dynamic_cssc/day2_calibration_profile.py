"""Derive the formal Day 2 pre-dispatch profile from admitted Day 1 evidence.

The public seam deliberately accepts paths only.  Source identities, candidate
topology, rotation indices, and claim-state flags are read from repository-owned
or provider-observed documents and are never caller parameters.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from contextlib import suppress
from dataclasses import asdict, dataclass
from pathlib import Path

from dynamic_cssc.day1_registry import (
    Day1CandidateRegistrationError,
    repository_day1_candidate_catalog,
)
from dynamic_cssc.day1a_export import (
    AUTHORITY_RECEIPT_FILENAME,
    COUNT_BUNDLE_FILENAME,
    ROTATION_INVENTORY_FILENAME,
)
from dynamic_cssc.day2_calibration_authority import (
    ABLATION_CANDIDATE_IDS,
    CALIBRATION_MEASUREMENT_BLOCK_COUNT,
    CALIBRATION_MEASUREMENT_STOP_RULE,
    CALIBRATION_OPERATION_ORDER_METHOD,
    CALIBRATION_OPERATION_ORDER_SEED,
    CALIBRATION_WARMUP_BLOCK_COUNT,
    EVIDENCE_SCOPE,
    FIXED_CANDIDATE_IDS,
    PRIMITIVE_NAMES,
    REFERENCE_CANDIDATE_IDS,
)
from dynamic_cssc.publication_artifact_install import (
    PublicationArtifactDirectory,
    PublicationArtifactInstallError,
    install_verified_directory,
    quarantine_owned_directory,
)
from dynamic_cssc.publication_primitive_accounting import (
    publication_primitive_accounting_contract_document,
)

__all__ = (
    "Day2CalibrationProfileDocuments",
    "Day2CalibrationProfileError",
    "Day2CalibrationProfileProposal",
    "propose_repository_day2_calibration_profile",
)

_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LOWER_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_ARTIFACT_NAME = re.compile(r"r2-day1a-publication-([0-9a-f]{40})-[0-9]{8}\Z")
_DAY1A_SCOPE = "synthetic-causal-count-and-exact-rotation-inventory-only"
_DAY1A_REPOSITORY = "leemaple/dynamic-cssc-spmv"
_DAY1A_REPOSITORY_ID = 1_341_939_625
_DAY1A_WORKFLOW_PATH = ".github/workflows/day1a-publication-cost-model.yml"
_DAY1_REGISTRATION_POLICY_SHA256 = (
    "a35cecd1553f53da9639a041d49d817c47bc9ae90aee269eaf2cd6f5daa8227b"
)
_PROPOSAL_MEMBERS = (
    "contract-bindings.json",
    "day2-calibration-profile-anchor-proposal.json",
    "operation-profile-set.json",
    "rotation-key-plan.json",
)
_PROPOSAL_MANIFEST = "PROFILE-MANIFEST.json"
_PROPOSAL_CHECKSUMS = "SHA256SUMS"
_PROPOSAL_FILES = frozenset((*_PROPOSAL_MEMBERS, _PROPOSAL_MANIFEST, _PROPOSAL_CHECKSUMS))

_DAY1A_COUNT_KEYS = frozenset(
    {
        "schema_version",
        "source_git_sha",
        "suite_status_sha256",
        "experiment_plan_sha256",
        "manifest_sha256",
        "measurement_kind",
        "state_model",
        "evidence_scope",
        "rows",
        "cols",
        "effective_slots",
        "partition_rows",
        "candidate_ids",
        "reference_candidate_ids",
        "ablation_candidate_ids",
        "metric_count_fields",
        "cell_count",
        "fixed_record_count",
        "records",
    }
)
_DAY1A_ROTATION_KEYS = frozenset(
    {
        "schema_version",
        "source_git_sha",
        "count_bundle_sha256",
        "rows",
        "cols",
        "effective_slots",
        "partition_rows",
        "publication_rows",
        "publication_cols",
        "publication_effective_slots",
        "publication_partition_rows",
        "publication_domain_match",
        "indices_in_range",
        "modulo_alias_free",
        "day2_direct_key_plan_eligible",
        "required_exact_indices",
        "measured_counts_by_exact_index",
        "candidate_required_exact_indices",
    }
)
_DAY1A_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "evidence_scope",
        "source_git_sha",
        "suite_status_sha256",
        "count_bundle_schema_version",
        "count_bundle_sha256",
        "rotation_inventory_schema_version",
        "rotation_inventory_sha256",
        "cell_count",
        "fixed_record_count",
        "day1a_count_evidence_authorized",
        "day2_direct_key_plan_authorized",
        "publication_domain_match",
        "complete_cost_claim_allowed",
        "formal_performance_claim_allowed",
        "paper_verdict_allowed",
        "security_claim_allowed",
    }
)
_REGISTRATION_KEYS = frozenset(
    {
        "schema_version",
        "source_git_sha",
        "run_id",
        "correctness_artifact_sha256",
        "accounting_evidence_sha256",
        "policy_contract_sha256",
    }
)
_METADATA_KEYS = frozenset(
    {
        "schema_version",
        "repository",
        "repository_id",
        "workflow_path",
        "workflow_file_sha256",
        "run_id",
        "run_attempt",
        "event_name",
        "ref",
        "head_sha",
        "artifact_name",
        "artifact_id",
        "artifact_digest",
    }
)

_ELEMENT_PRIMITIVES = frozenset(
    {
        "client_merge",
        "client_reorder_element",
        "mask_map_element",
        "mask_random_element",
        "query_vector_pack",
    }
)
_TIMED_OPERATIONS = {
    "client_merge": "modularly add one 4096-element client result vector",
    "client_reorder_element": "reorder one 4096-element client result vector",
    "decrypt": "decrypt one admitted BFVRNS ciphertext",
    "deserialize_ciphertext": "deserialize one admitted BFVRNS ciphertext",
    "encode": "encode one admitted 8192-slot packed plaintext",
    "encrypt": "encrypt one admitted BFVRNS plaintext",
    "eval_add_ciphertext": "add two admitted BFVRNS ciphertexts",
    "eval_mult_plaintext_mask": "multiply one ciphertext by one packed plaintext mask",
    "eval_mult_with_relinearization": (
        "multiply two ciphertexts and relinearize exactly once"
    ),
    "eval_rotate": "rotate one ciphertext by one exact pre-dispatch index",
    "mask_map_element": "map one sampled mask element into the plaintext field",
    "mask_random_element": "sample one unbiased mask element from the operating-system CSPRNG",
    "query_vector_pack": "pack one 4096-element query vector into the admitted slot layout",
    "serialize_ciphertext": "serialize one admitted BFVRNS ciphertext",
}
_CORRECTNESS_RULES = {
    "client_merge": "output-equals-elementwise-modular-sum",
    "client_reorder_element": "output-equals-frozen-output-plan-permutation",
    "decrypt": "centered-lifted-decryption-equals-fixture-plaintext",
    "deserialize_ciphertext": "roundtrip-ciphertext-decrypts-to-fixture-plaintext",
    "encode": "decoded-packed-plaintext-equals-fixture-vector",
    "encrypt": "decryption-equals-fixture-plaintext",
    "eval_add_ciphertext": "decryption-equals-elementwise-modular-sum",
    "eval_mult_plaintext_mask": "decryption-equals-elementwise-plaintext-mask-product",
    "eval_mult_with_relinearization": (
        "decryption-equals-elementwise-product-and-relinearized-size-is-two"
    ),
    "eval_rotate": "decryption-equals-exact-cyclic-slot-rotation",
    "mask_map_element": "mapped-element-is-in-canonical-plaintext-residue-domain",
    "mask_random_element": "sample-is-in-domain-and-rejection-path-is-bias-free",
    "query_vector_pack": "decoded-slots-equal-frozen-query-vector-layout",
    "serialize_ciphertext": "roundtrip-ciphertext-decrypts-to-fixture-plaintext",
}
_SERIALIZED_OBJECT_CATEGORIES = (
    ("update-column-index-synchronization", "update"),
    ("update-publication-ciphertexts", "update"),
    ("update-version-plan-metadata", "update"),
    ("query-query-ciphertexts", "query"),
    ("query-result-ciphertexts", "query"),
    ("query-f1m-random-mask-ciphertexts", "query"),
    ("query-f1m-encrypted-zero-dummy-ciphertexts", "query"),
    ("query-version-plan-metadata", "query"),
    ("one-time-evaluation-key-material", "one-time"),
)


class Day2CalibrationProfileError(ValueError):
    """A formal pre-dispatch profile could not be derived without ambiguity."""


@dataclass(frozen=True, slots=True)
class Day2CalibrationProfileDocuments:
    """The four canonical documents determined before Day 2 dispatch."""

    operation_profile_set: dict[str, object]
    rotation_key_plan: dict[str, object]
    contract_bindings: dict[str, object]
    profile_anchor: dict[str, object]


@dataclass(frozen=True, slots=True)
class Day2CalibrationProfileProposal:
    """Identity of one atomically installed, review-only profile proposal."""

    output_dir: Path
    operation_profile_set_sha256: str
    rotation_key_plan_sha256: str
    contract_bindings_sha256: str
    profile_anchor_sha256: str
    manifest_sha256: str
    checksums_sha256: str
    formal_authority_granted: bool = False


def _canonical_json_bytes(value: object) -> bytes:
    try:
        content = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise Day2CalibrationProfileError("profile value is not canonical JSON") from error
    return (content + "\n").encode("ascii")


def _sha256(value: object) -> str:
    content = value if isinstance(value, bytes) else _canonical_json_bytes(value)
    return hashlib.sha256(content).hexdigest()


def _exact_object(value: object, keys: frozenset[str], field: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise Day2CalibrationProfileError(f"{field} keys do not match the closed schema")
    return value


def _lower_sha256(value: object, field: str) -> str:
    if type(value) is not str or _LOWER_SHA256.fullmatch(value) is None:
        raise Day2CalibrationProfileError(f"{field} must be a lowercase SHA-256")
    return value


def _lower_git_sha(value: object, field: str) -> str:
    if type(value) is not str or _LOWER_GIT_SHA.fullmatch(value) is None:
        raise Day2CalibrationProfileError(f"{field} must be a full lowercase Git SHA")
    return value


def _positive_int(value: object, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise Day2CalibrationProfileError(f"{field} must be a positive strict integer")
    return value


def _string_list(value: object, field: str) -> list[str]:
    if type(value) is not list or any(type(item) is not str or not item for item in value):
        raise Day2CalibrationProfileError(f"{field} must contain nonempty strings")
    if len(value) != len(set(value)):
        raise Day2CalibrationProfileError(f"{field} must not contain duplicates")
    return list(value)


def _validate_candidate_topology(count_bundle: dict[str, object]) -> None:
    fixed = _string_list(count_bundle["candidate_ids"], "Day1A candidate IDs")
    references = _string_list(
        count_bundle["reference_candidate_ids"], "Day1A reference candidate IDs"
    )
    ablations = _string_list(
        count_bundle["ablation_candidate_ids"], "Day1A ablation candidate IDs"
    )
    if (
        len(fixed) != 14
        or len(references) != 13
        or len(ablations) != 1
        or set(fixed) != set(FIXED_CANDIDATE_IDS)
        or set(references) != set(REFERENCE_CANDIDATE_IDS)
        or tuple(ablations) != ABLATION_CANDIDATE_IDS
        or set(references) | set(ablations) != set(fixed)
        or set(references) & set(ablations)
    ):
        raise Day2CalibrationProfileError(
            "Day1A candidate topology is not the frozen 14/13/1 candidate set"
        )


def _validate_count_bundle(value: object) -> dict[str, object]:
    count = _exact_object(value, _DAY1A_COUNT_KEYS, "Day1A count bundle")
    if count["schema_version"] != "dynamic-cssc-day1a-count-bundle-v1":
        raise Day2CalibrationProfileError("Day1A count-bundle schema is not frozen")
    _lower_git_sha(count["source_git_sha"], "Day1A count-bundle source")
    for field in ("suite_status_sha256", "experiment_plan_sha256", "manifest_sha256"):
        _lower_sha256(count[field], f"Day1A count-bundle {field}")
    if (
        count["measurement_kind"] != "predicted-proxy"
        or count["state_model"] != "persistent-strategy-snapshots"
        or count["evidence_scope"] != _DAY1A_SCOPE
    ):
        raise Day2CalibrationProfileError("Day1A count-bundle evidence semantics are not frozen")
    expected_domain = {
        "rows": 4096,
        "cols": 8193,
        "effective_slots": 4096,
        "partition_rows": 4096,
    }
    for field, expected in expected_domain.items():
        if type(count[field]) is not int or count[field] != expected:
            raise Day2CalibrationProfileError(
                f"Day1A count-bundle {field} does not match the publication domain"
            )
    _validate_candidate_topology(count)
    if type(count["metric_count_fields"]) is not list or any(
        type(item) is not str or not item for item in count["metric_count_fields"]
    ):
        raise Day2CalibrationProfileError("Day1A metric-count vocabulary is invalid")
    for field in ("cell_count", "fixed_record_count"):
        _positive_int(count[field], f"Day1A count-bundle {field}")
    if type(count["records"]) is not list:
        raise Day2CalibrationProfileError("Day1A count-bundle records must be a list")
    return count


def _validate_rotation_inventory(
    value: object,
    *,
    count_bundle: dict[str, object],
) -> tuple[dict[str, object], list[int]]:
    rotation = _exact_object(value, _DAY1A_ROTATION_KEYS, "Day1A rotation inventory")
    if rotation["schema_version"] != "dynamic-cssc-day1a-rotation-inventory-v1":
        raise Day2CalibrationProfileError("Day1A rotation-inventory schema is not frozen")
    if rotation["source_git_sha"] != count_bundle["source_git_sha"]:
        raise Day2CalibrationProfileError("Day1A rotation and count source SHAs differ")
    if rotation["count_bundle_sha256"] != _sha256(count_bundle):
        raise Day2CalibrationProfileError("Day1A rotation count bundle digest does not match")
    expected_domain = {
        "rows": 4096,
        "cols": 8193,
        "effective_slots": 4096,
        "partition_rows": 4096,
        "publication_rows": 4096,
        "publication_cols": 8193,
        "publication_effective_slots": 4096,
        "publication_partition_rows": 4096,
    }
    for field, expected in expected_domain.items():
        if type(rotation[field]) is not int or rotation[field] != expected:
            raise Day2CalibrationProfileError(
                f"Day1A rotation {field} does not match the publication domain"
            )
    for field in (
        "publication_domain_match",
        "indices_in_range",
        "modulo_alias_free",
        "day2_direct_key_plan_eligible",
    ):
        if rotation[field] is not True:
            label = field.replace("_", " ")
            raise Day2CalibrationProfileError(f"Day1A rotation {label} must be true")
    required = rotation["required_exact_indices"]
    if type(required) is not list or any(type(index) is not int for index in required):
        raise Day2CalibrationProfileError("required rotation indices must be strict integers")
    if (
        not required
        or required != sorted(set(required))
        or any(index == 0 or not -4095 <= index <= 4095 for index in required)
    ):
        raise Day2CalibrationProfileError(
            "required rotation indices must be canonical, nonzero, and in range"
        )
    if len({index % 4096 for index in required}) != len(required):
        raise Day2CalibrationProfileError("required rotation indices contain modulo aliases")
    measured = rotation["measured_counts_by_exact_index"]
    if type(measured) is not list or any(
        type(row) is not list
        or len(row) != 2
        or type(row[0]) is not int
        or type(row[1]) is not int
        or row[1] <= 0
        for row in measured
    ):
        raise Day2CalibrationProfileError("Day1A measured rotation counts are invalid")
    if measured != sorted(measured) or len({row[0] for row in measured}) != len(measured):
        raise Day2CalibrationProfileError("Day1A measured rotation counts are not canonical")
    if any(row[0] not in required for row in measured):
        raise Day2CalibrationProfileError("Day1A measured rotations exceed the required inventory")
    if type(rotation["candidate_required_exact_indices"]) is not list:
        raise Day2CalibrationProfileError("Day1A per-candidate rotation inventory is invalid")
    return rotation, list(required)


def _validate_receipt(
    value: object,
    *,
    count_bundle: dict[str, object],
    rotation_inventory: dict[str, object],
) -> dict[str, object]:
    receipt = _exact_object(value, _DAY1A_RECEIPT_KEYS, "Day1A authority receipt")
    if (
        receipt["schema_version"] != "dynamic-cssc-day1a-authority-receipt-v1"
        or receipt["status"] != "pass"
        or receipt["evidence_scope"] != _DAY1A_SCOPE
    ):
        raise Day2CalibrationProfileError("Day1A authority receipt is not an exact pass receipt")
    source = _lower_git_sha(receipt["source_git_sha"], "Day1A receipt source")
    if source != count_bundle["source_git_sha"] or source != rotation_inventory["source_git_sha"]:
        raise Day2CalibrationProfileError("Day1A receipt and payload source SHAs differ")
    if (
        receipt["suite_status_sha256"] != count_bundle["suite_status_sha256"]
        or receipt["count_bundle_schema_version"] != count_bundle["schema_version"]
        or receipt["rotation_inventory_schema_version"] != rotation_inventory["schema_version"]
        or receipt["count_bundle_sha256"] != _sha256(count_bundle)
        or receipt["rotation_inventory_sha256"] != _sha256(rotation_inventory)
    ):
        raise Day2CalibrationProfileError("Day1A receipt payload digest binding does not match")
    if (
        receipt["cell_count"] != count_bundle["cell_count"]
        or receipt["fixed_record_count"] != count_bundle["fixed_record_count"]
    ):
        raise Day2CalibrationProfileError("Day1A receipt record counts do not match")
    for field in (
        "day1a_count_evidence_authorized",
        "day2_direct_key_plan_authorized",
        "publication_domain_match",
    ):
        if receipt[field] is not True:
            raise Day2CalibrationProfileError(f"Day1A receipt {field} is not authorized")
    for field in (
        "complete_cost_claim_allowed",
        "formal_performance_claim_allowed",
        "paper_verdict_allowed",
        "security_claim_allowed",
    ):
        if receipt[field] is not False:
            raise Day2CalibrationProfileError(f"Day1A receipt {field} must remain false")
    return receipt


def _validate_registration(value: object) -> dict[str, object]:
    registration = _exact_object(value, _REGISTRATION_KEYS, "Day 1 registration evidence")
    if registration["schema_version"] != "dynamic-cssc-day1-registration-evidence-v1":
        raise Day2CalibrationProfileError("Day 1 registration schema is not frozen")
    _lower_git_sha(registration["source_git_sha"], "Day 1 registration source")
    _positive_int(registration["run_id"], "Day 1 registration run ID")
    for field in (
        "correctness_artifact_sha256",
        "accounting_evidence_sha256",
        "policy_contract_sha256",
    ):
        _lower_sha256(registration[field], f"Day 1 registration {field}")
    if registration["policy_contract_sha256"] != _DAY1_REGISTRATION_POLICY_SHA256:
        raise Day2CalibrationProfileError("Day 1 registration policy contract is not frozen")
    return registration


def _validate_metadata(value: object, *, source_git_sha: str) -> dict[str, object]:
    metadata = _exact_object(value, _METADATA_KEYS, "Day1A GitHub artifact metadata")
    if (
        metadata["schema_version"] != "dynamic-cssc-day1a-github-artifact-metadata-v1"
        or metadata["repository"] != _DAY1A_REPOSITORY
        or metadata["repository_id"] != _DAY1A_REPOSITORY_ID
        or metadata["workflow_path"] != _DAY1A_WORKFLOW_PATH
        or metadata["event_name"] != "workflow_dispatch"
        or metadata["ref"] != "refs/heads/main"
    ):
        raise Day2CalibrationProfileError("Day1A provider metadata is not the frozen workflow")
    _lower_sha256(metadata["workflow_file_sha256"], "Day1A workflow file")
    for field in ("run_id", "run_attempt", "artifact_id"):
        _positive_int(metadata[field], f"Day1A provider metadata {field}")
    if metadata["head_sha"] != source_git_sha:
        raise Day2CalibrationProfileError("Day1A provider head SHA does not match the receipt")
    match = (
        _ARTIFACT_NAME.fullmatch(metadata["artifact_name"])
        if type(metadata["artifact_name"]) is str
        else None
    )
    if match is None or match.group(1) != source_git_sha:
        raise Day2CalibrationProfileError("Day1A artifact name does not bind the head SHA")
    digest = metadata["artifact_digest"]
    if type(digest) is not str or not digest.startswith("sha256:"):
        raise Day2CalibrationProfileError("Day1A artifact digest is not a SHA-256")
    _lower_sha256(digest.removeprefix("sha256:"), "Day1A artifact digest")
    return metadata


def _repository_contract_documents(repository_root: Path) -> tuple[dict[str, object], ...]:
    if not isinstance(repository_root, Path) or not repository_root.is_dir():
        raise Day2CalibrationProfileError("repository_root must be a directory")
    paths = (
        repository_root / "config/params_manifest.json",
        repository_root / "config/experiment_plan_publication.json",
    )
    contents: list[bytes] = []
    decoded: list[dict[str, object]] = []
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise Day2CalibrationProfileError(f"repository contract is unavailable: {path.name}")
        content = path.read_bytes()
        try:
            value = json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise Day2CalibrationProfileError(
                f"repository contract is not valid JSON: {path.name}"
            ) from error
        if type(value) is not dict:
            raise Day2CalibrationProfileError(
                f"repository contract must be an object: {path.name}"
            )
        contents.append(content)
        decoded.append(value)
    params, plan = decoded
    openfhe = params.get("openfhe")
    packing = params.get("packing")
    matrix = params.get("matrix")
    synthetic = plan.get("synthetic")
    if (
        type(openfhe) is not dict
        or openfhe.get("version") != "1.5.1"
        or openfhe.get("commit") != "1306d14f8c26bb6150d3e6ad54f28dfe1007689e"
        or openfhe.get("scheme") != "BFVRNS"
        or openfhe.get("ring_dimension") != 8192
        or openfhe.get("plaintext_modulus") != 65537
        or openfhe.get("batch_size") != 8192
        or type(packing) is not dict
        or packing.get("effective_slots") != 4096
        or type(matrix) is not dict
        or matrix.get("rows") != 4096
        or matrix.get("cols") != 8193
        or type(synthetic) is not dict
        or synthetic.get("rows") != 4096
        or synthetic.get("cols") != 8193
        or synthetic.get("effective_slots") != 4096
        or synthetic.get("partition_rows") != 4096
    ):
        raise Day2CalibrationProfileError("repository publication parameter domain is not frozen")
    experiment_contract = {
        "schema_version": "dynamic-cssc-publication-day2-experiment-contract-v1",
        "evidence_scope": EVIDENCE_SCOPE,
        "params_manifest_sha256": _sha256(contents[0]),
        "experiment_plan_publication_sha256": _sha256(contents[1]),
        "openfhe_repository": openfhe["repository"],
        "openfhe_version": openfhe["version"],
        "openfhe_commit": openfhe["commit"],
        "scheme": openfhe["scheme"],
        "ring_dimension": openfhe["ring_dimension"],
        "plaintext_modulus": openfhe["plaintext_modulus"],
        "batch_size": openfhe["batch_size"],
        "effective_slots": 4096,
        "publication_rows": 4096,
        "publication_cols": 8193,
        "warmup_block_count": CALIBRATION_WARMUP_BLOCK_COUNT,
        "measurement_block_count": CALIBRATION_MEASUREMENT_BLOCK_COUNT,
        "measurement_stop_rule": CALIBRATION_MEASUREMENT_STOP_RULE,
        "operation_order_seed": CALIBRATION_OPERATION_ORDER_SEED,
        "operation_order_method": CALIBRATION_OPERATION_ORDER_METHOD,
    }
    primitive_accounting = publication_primitive_accounting_contract_document()
    serialized_accounting = {
        "schema_version": "dynamic-cssc-publication-serialized-object-accounting-v1",
        "categories": [
            {"category": category, "transaction": transaction}
            for category, transaction in _SERIALIZED_OBJECT_CATEGORIES
        ],
        "primary_byte_rule": "exact-canonical-protocol-object-serialization-length",
        "framing_exclusions": ["artifact-container", "filesystem", "http", "tls", "workflow"],
        "one_time_key_rule": "reported-separately-not-amortized-in-primary-C",
    }
    candidate_catalog = {
        "schema_version": "dynamic-cssc-day1-candidate-catalog-v1",
        "fixed_candidate_ids": list(FIXED_CANDIDATE_IDS),
        "reference_candidate_ids": list(REFERENCE_CANDIDATE_IDS),
        "ablation_candidate_ids": list(ABLATION_CANDIDATE_IDS),
    }
    return experiment_contract, primitive_accounting, serialized_accounting, candidate_catalog


def _fixture_contract(
    *,
    primitive_name: str,
    case_id: str,
    experiment_contract_sha256: str,
) -> dict[str, object]:
    return {
        "schema_version": "dynamic-cssc-publication-day2-input-fixture-contract-v1",
        "primitive_name": primitive_name,
        "case_id": case_id,
        "experiment_contract_sha256": experiment_contract_sha256,
        "fixture_domain": "bfvrns-8192-slots-4096-effective-publication-domain",
        "fixture_values": "repository-probe-owned-deterministic-nonsecret-pattern-v1",
        "cryptographic_randomness": (
            "operating-system-csprng"
            if primitive_name in {"encrypt", "mask_random_element"}
            else "not-applicable-or-setup-only"
        ),
    }


def _operation_profile_set(
    *,
    rotation_indices: list[int],
    experiment_contract_sha256: str,
) -> dict[str, object]:
    profiles: list[dict[str, object]] = []
    for primitive_name in PRIMITIVE_NAMES:
        case_ids = (
            [f"index={index}" for index in rotation_indices]
            if primitive_name == "eval_rotate"
            else ["admitted-case"]
        )
        correctness_contract = {
            "schema_version": "dynamic-cssc-publication-day2-correctness-check-v1",
            "primitive_name": primitive_name,
            "rule": _CORRECTNESS_RULES[primitive_name],
            "all-cases-required": True,
        }
        profiles.append(
            {
                "primitive_name": primitive_name,
                "profile_id": f"publication/{primitive_name}/v2",
                "setup_scope": "outside-timed-region",
                "timed_operation": _TIMED_OPERATIONS[primitive_name],
                "case_aggregation_rule": (
                    "per-block-max-over-all-exact-indices"
                    if primitive_name == "eval_rotate"
                    else "per-block-max-over-all-admitted-cases"
                ),
                "warmup_policy": "complete-profile-blocks-before-measurement",
                "measurement_policy": "elapsed-ns-divided-by-operation-count",
                "includes_relinearization": (
                    primitive_name == "eval_mult_with_relinearization"
                ),
                "randomness_policy": (
                    "operating-system-csprng-unbiased-rejection-sampling"
                    if primitive_name == "mask_random_element"
                    else "not-applicable"
                ),
                "correctness_check_sha256": _sha256(correctness_contract),
                "cases": [
                    {
                        "case_id": case_id,
                        "unit_definition": (
                            "one element in a complete 4096-element timed loop"
                            if primitive_name in _ELEMENT_PRIMITIVES
                            else _TIMED_OPERATIONS[primitive_name]
                        ),
                        "input_fixture_contract_sha256": _sha256(
                            _fixture_contract(
                                primitive_name=primitive_name,
                                case_id=case_id,
                                experiment_contract_sha256=experiment_contract_sha256,
                            )
                        ),
                        "operation_count": (
                            4096 if primitive_name in _ELEMENT_PRIMITIVES else 1
                        ),
                    }
                    for case_id in case_ids
                ],
            }
        )
    return {
        "schema_version": "dynamic-cssc-publication-operation-profile-set-v2",
        "primitive_names": list(PRIMITIVE_NAMES),
        "warmup_block_count": CALIBRATION_WARMUP_BLOCK_COUNT,
        "measurement_block_count": CALIBRATION_MEASUREMENT_BLOCK_COUNT,
        "measurement_stop_rule": CALIBRATION_MEASUREMENT_STOP_RULE,
        "operation_order_seed": CALIBRATION_OPERATION_ORDER_SEED,
        "operation_order_method": CALIBRATION_OPERATION_ORDER_METHOD,
        "profiles": profiles,
    }


def _derive_day2_profile_documents(
    *,
    repository_root: Path,
    day1a_authority_receipt: object,
    day1a_rotation_inventory: object,
    day1a_count_bundle: object,
    registration_evidence: object,
    day1a_artifact_metadata: object,
) -> Day2CalibrationProfileDocuments:
    """Purely derive the complete pre-dispatch profile from closed inputs."""

    count_bundle = _validate_count_bundle(day1a_count_bundle)
    rotation_inventory, required_indices = _validate_rotation_inventory(
        day1a_rotation_inventory,
        count_bundle=count_bundle,
    )
    receipt = _validate_receipt(
        day1a_authority_receipt,
        count_bundle=count_bundle,
        rotation_inventory=rotation_inventory,
    )
    registration = _validate_registration(registration_evidence)
    metadata = _validate_metadata(
        day1a_artifact_metadata,
        source_git_sha=receipt["source_git_sha"],
    )
    (
        experiment_contract,
        primitive_accounting,
        serialized_accounting,
        candidate_catalog,
    ) = _repository_contract_documents(repository_root)
    experiment_contract_sha256 = _sha256(experiment_contract)
    rotation_plan = {
        "schema_version": "dynamic-cssc-publication-rotation-key-plan-v2",
        "inventory_source_schema_version": rotation_inventory["schema_version"],
        "day1a_authority_receipt_sha256": _sha256(receipt),
        "day1a_inventory_sha256": _sha256(rotation_inventory),
        "effective_slots": 4096,
        "required_exact_indices": required_indices,
        "key_plan_kind": "direct-exact-index-v1",
        "planned_exact_indices": required_indices,
        "composite_decompositions": [],
        "eval_rotate_case_ids": [f"index={index}" for index in required_indices],
    }
    profiles = _operation_profile_set(
        rotation_indices=required_indices,
        experiment_contract_sha256=experiment_contract_sha256,
    )
    contract = {
        "schema_version": "dynamic-cssc-publication-day2-contract-bindings-v1",
        "experiment_contract_sha256": experiment_contract_sha256,
        "day1_candidate_registration_receipt_sha256": _sha256(registration),
        "candidate_catalog_schema_version": candidate_catalog["schema_version"],
        "candidate_catalog_sha256": _sha256(candidate_catalog),
        "fixed_candidate_ids": list(FIXED_CANDIDATE_IDS),
        "reference_candidate_ids": list(REFERENCE_CANDIDATE_IDS),
        "ablation_candidate_ids": list(ABLATION_CANDIDATE_IDS),
        "day1a_count_bundle_schema_version": count_bundle["schema_version"],
        "day1a_count_bundle_sha256": _sha256(count_bundle),
        "heldout_record_schema_version": "dynamic-cssc-publication-heldout-record-v4",
        "primitive_accounting_schema_version": primitive_accounting["schema_version"],
        "primitive_accounting_mapping_sha256": _sha256(primitive_accounting),
        "serialized_object_accounting_schema_version": serialized_accounting[
            "schema_version"
        ],
        "serialized_object_accounting_contract_sha256": _sha256(serialized_accounting),
        "day1a_rotation_inventory_sha256": _sha256(rotation_inventory),
        "rotation_key_plan_sha256": _sha256(rotation_plan),
    }
    anchor = {
        "schema_version": "dynamic-cssc-day2-calibration-profile-anchor-v3",
        "operation_profile_set_sha256": _sha256(profiles),
        "warmup_block_count": CALIBRATION_WARMUP_BLOCK_COUNT,
        "rotation_key_plan_sha256": _sha256(rotation_plan),
        "rotation_inventory_source_schema_version": rotation_inventory["schema_version"],
        "day1a_authority_receipt_sha256": _sha256(receipt),
        "day1a_inventory_sha256": _sha256(rotation_inventory),
        "contract_bindings_sha256": _sha256(contract),
        "experiment_contract_sha256": contract["experiment_contract_sha256"],
        "day1_candidate_registration_receipt_sha256": contract[
            "day1_candidate_registration_receipt_sha256"
        ],
        "candidate_catalog_schema_version": contract["candidate_catalog_schema_version"],
        "candidate_catalog_sha256": contract["candidate_catalog_sha256"],
        "day1a_count_bundle_schema_version": contract["day1a_count_bundle_schema_version"],
        "day1a_count_bundle_sha256": contract["day1a_count_bundle_sha256"],
        "heldout_record_schema_version": contract["heldout_record_schema_version"],
        "primitive_accounting_schema_version": contract[
            "primitive_accounting_schema_version"
        ],
        "primitive_accounting_mapping_sha256": contract[
            "primitive_accounting_mapping_sha256"
        ],
        "serialized_object_accounting_schema_version": contract[
            "serialized_object_accounting_schema_version"
        ],
        "serialized_object_accounting_contract_sha256": contract[
            "serialized_object_accounting_contract_sha256"
        ],
        "day1a_workflow_run_id": metadata["run_id"],
        "day1a_artifact_id": metadata["artifact_id"],
        "day1a_artifact_name": metadata["artifact_name"],
        "day1a_artifact_digest": metadata["artifact_digest"],
    }
    return Day2CalibrationProfileDocuments(
        operation_profile_set=profiles,
        rotation_key_plan=rotation_plan,
        contract_bindings=contract,
        profile_anchor=anchor,
    )


def _decode_canonical_path(path: Path, field: str, *, maximum_bytes: int) -> dict[str, object]:
    if not isinstance(path, Path) or path.is_symlink() or not path.is_file():
        raise Day2CalibrationProfileError(f"{field} must be a regular non-symlink file")
    content = path.read_bytes()
    if not content or len(content) > maximum_bytes:
        raise Day2CalibrationProfileError(f"{field} exceeds its closed byte bound")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        decoded: dict[str, object] = {}
        for key, value in pairs:
            if key in decoded:
                raise Day2CalibrationProfileError(f"{field} contains a duplicate JSON key")
            decoded[key] = value
        return decoded

    try:
        value = json.loads(content, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Day2CalibrationProfileError(f"{field} is not readable JSON") from error
    if type(value) is not dict or _canonical_json_bytes(value) != content:
        raise Day2CalibrationProfileError(f"{field} is not canonical JSON")
    return value


def _proposal_documents(documents: Day2CalibrationProfileDocuments) -> dict[str, bytes]:
    payloads = {
        "contract-bindings.json": _canonical_json_bytes(documents.contract_bindings),
        "day2-calibration-profile-anchor-proposal.json": _canonical_json_bytes(
            {
                "schema_version": "dynamic-cssc-day2-calibration-profile-anchor-set-v3",
                "anchors": [documents.profile_anchor],
            }
        ),
        "operation-profile-set.json": _canonical_json_bytes(
            documents.operation_profile_set
        ),
        "rotation-key-plan.json": _canonical_json_bytes(documents.rotation_key_plan),
    }
    manifest = {
        "schema_version": "dynamic-cssc-day2-calibration-profile-proposal-manifest-v1",
        "formal_authority_granted": False,
        "files": [
            {"path": name, "sha256": _sha256(payloads[name]), "bytes": len(payloads[name])}
            for name in _PROPOSAL_MEMBERS
        ],
    }
    payloads[_PROPOSAL_MANIFEST] = _canonical_json_bytes(manifest)
    checksummed = sorted((*_PROPOSAL_MEMBERS, _PROPOSAL_MANIFEST))
    payloads[_PROPOSAL_CHECKSUMS] = "".join(
        f"{_sha256(payloads[name])}  {name}\n" for name in checksummed
    ).encode("ascii")
    return payloads


def _write_new_file(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


def _verify_proposal_view(
    view: PublicationArtifactDirectory,
    *,
    expected: dict[str, bytes],
) -> tuple[tuple[str, str], ...]:
    if frozenset(view.entries()) != _PROPOSAL_FILES:
        raise Day2CalibrationProfileError("profile proposal member set is not closed")
    observed: list[tuple[str, str]] = []
    for name in sorted(expected):
        content = view.read_regular(name)
        if content != expected[name]:
            raise Day2CalibrationProfileError(f"profile proposal member changed: {name}")
        observed.append((name, _sha256(content)))
    return tuple(observed)


def _install_proposal(
    output_dir: Path,
    documents: Day2CalibrationProfileDocuments,
) -> Day2CalibrationProfileProposal:
    if not isinstance(output_dir, Path):
        raise TypeError("output_directory must be a pathlib.Path")
    output_dir = output_dir.absolute()
    parent = output_dir.parent
    if parent.is_symlink() or not parent.is_dir():
        raise Day2CalibrationProfileError("profile proposal parent must be a regular directory")
    if output_dir.exists() or output_dir.is_symlink():
        raise Day2CalibrationProfileError("profile proposal output must be absent")
    rendered = _proposal_documents(documents)
    stage: Path | None = None
    identity: tuple[int, int] | None = None
    try:
        stage = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.stage-", dir=parent))
        observed = stage.stat(follow_symlinks=False)
        identity = (observed.st_dev, observed.st_ino)
        for name in sorted(rendered):
            _write_new_file(stage / name, rendered[name])
        directory_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

        def verifier(view: PublicationArtifactDirectory) -> tuple[tuple[str, str], ...]:
            return _verify_proposal_view(view, expected=rendered)

        install_verified_directory(
            stage,
            output_dir,
            staging_identity=identity,
            verifier=verifier,
            fingerprint=lambda value: value,
        )
        stage = None
    except PublicationArtifactInstallError as error:
        raise Day2CalibrationProfileError(
            "profile proposal installation failed closed"
        ) from error
    finally:
        if stage is not None and identity is not None:
            with suppress(OSError, PublicationArtifactInstallError):
                quarantine_owned_directory(stage, staging_identity=identity)
    return Day2CalibrationProfileProposal(
        output_dir=output_dir,
        operation_profile_set_sha256=_sha256(rendered["operation-profile-set.json"]),
        rotation_key_plan_sha256=_sha256(rendered["rotation-key-plan.json"]),
        contract_bindings_sha256=_sha256(rendered["contract-bindings.json"]),
        profile_anchor_sha256=_sha256(
            rendered["day2-calibration-profile-anchor-proposal.json"]
        ),
        manifest_sha256=_sha256(rendered[_PROPOSAL_MANIFEST]),
        checksums_sha256=_sha256(rendered[_PROPOSAL_CHECKSUMS]),
    )


def propose_repository_day2_calibration_profile(
    day1a_directory: Path,
    github_artifact_metadata_path: Path,
    output_directory: Path,
) -> Day2CalibrationProfileProposal:
    """Create a review-only proposal from one selected formal Day 1A artifact."""

    if not isinstance(day1a_directory, Path):
        raise TypeError("day1a_directory must be a pathlib.Path")
    if day1a_directory.is_symlink() or not day1a_directory.is_dir():
        raise Day2CalibrationProfileError(
            "day1a_directory must be a regular non-symlink directory"
        )
    count_bundle = _decode_canonical_path(
        day1a_directory / COUNT_BUNDLE_FILENAME,
        COUNT_BUNDLE_FILENAME,
        maximum_bytes=64 * 1024 * 1024,
    )
    rotation_inventory = _decode_canonical_path(
        day1a_directory / ROTATION_INVENTORY_FILENAME,
        ROTATION_INVENTORY_FILENAME,
        maximum_bytes=8 * 1024 * 1024,
    )
    receipt = _decode_canonical_path(
        day1a_directory / AUTHORITY_RECEIPT_FILENAME,
        AUTHORITY_RECEIPT_FILENAME,
        maximum_bytes=1024 * 1024,
    )
    metadata = _decode_canonical_path(
        github_artifact_metadata_path,
        "Day1A GitHub artifact metadata",
        maximum_bytes=1024 * 1024,
    )
    try:
        catalog = repository_day1_candidate_catalog()
    except Day1CandidateRegistrationError as error:
        raise Day2CalibrationProfileError(
            "repository Day 1 candidate registration is not authoritative"
        ) from error
    catalog_ids = tuple(candidate.candidate_id for candidate in catalog.candidates)
    reference_ids = tuple(candidate.candidate_id for candidate in catalog.selection_candidates)
    ablation_ids = tuple(candidate.candidate_id for candidate in catalog.ablation_candidates)
    if (
        catalog_ids != FIXED_CANDIDATE_IDS
        or reference_ids != REFERENCE_CANDIDATE_IDS
        or ablation_ids != ABLATION_CANDIDATE_IDS
    ):
        raise Day2CalibrationProfileError("repository candidate catalog topology changed")
    documents = _derive_day2_profile_documents(
        repository_root=Path(__file__).resolve().parents[2],
        day1a_authority_receipt=receipt,
        day1a_rotation_inventory=rotation_inventory,
        day1a_count_bundle=count_bundle,
        registration_evidence=asdict(catalog.registration),
        day1a_artifact_metadata=metadata,
    )
    return _install_proposal(output_directory, documents)
