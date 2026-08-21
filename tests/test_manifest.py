from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

import pytest

from dynamic_cssc.manifest import ManifestError, load_manifest, validate_manifest

ROOT = Path(__file__).resolve().parents[1]

MASK_BINDING = [
    "query_id",
    "version_id",
    "output_plan_digest",
    "component_id",
    "output_block_id",
]


def _schema_accepts(value: object, schema: dict[str, Any]) -> bool:
    """Evaluate the deliberately small JSON-Schema subset used by this manifest."""

    if "const" in schema and value != schema["const"]:
        return False
    if "enum" in schema and value not in schema["enum"]:
        return False

    expected_type = schema.get("type")
    if expected_type == "object":
        if not isinstance(value, dict):
            return False
        required = set(schema.get("required", []))
        if not required <= value.keys():
            return False
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False and not value.keys() <= properties.keys():
            return False
        return all(
            key not in value or _schema_accepts(value[key], subschema)
            for key, subschema in properties.items()
        )
    if expected_type == "array":
        if not isinstance(value, list):
            return False
        if len(value) < schema.get("minItems", 0):
            return False
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            return False
        unique_count = len({json.dumps(item, sort_keys=True) for item in value})
        if schema.get("uniqueItems") and unique_count != len(value):
            return False
        item_schema = schema.get("items")
        return item_schema is None or all(_schema_accepts(item, item_schema) for item in value)
    if expected_type == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            return False
        return value >= schema.get("minimum", value) and value <= schema.get("maximum", value)
    if expected_type == "number":
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return False
        return value > schema.get("exclusiveMinimum", value - 1)
    if expected_type == "boolean":
        return isinstance(value, bool)
    if expected_type == "string":
        if not isinstance(value, str) or len(value) < schema.get("minLength", 0):
            return False
        return "pattern" not in schema or re.search(schema["pattern"], value) is not None
    return True


def _assert_all_objects_are_closed(schema: dict[str, Any], context: str = "root") -> None:
    if schema.get("type") == "object":
        assert schema.get("additionalProperties") is False, context
        properties = schema.get("properties", {})
        assert set(schema.get("required", [])) == set(properties), context
        for name, child in properties.items():
            _assert_all_objects_are_closed(child, f"{context}.{name}")
    if schema.get("type") == "array" and isinstance(schema.get("items"), dict):
        _assert_all_objects_are_closed(schema["items"], f"{context}[]")


def test_frozen_manifest_is_valid() -> None:
    data = load_manifest(ROOT / "config" / "params_manifest.json")
    assert data["manifest_version"] == "0.2.0"
    assert data["protocol_version"] == "2.1b"
    assert data["functional_mode"] == "F1-M-hidden-rowmap"
    assert data["openfhe"]["plaintext_modulus"] > data["packing"]["total_slots"]
    assert data["matrix"]["cols"] == 8193 > data["packing"]["effective_slots"]
    profiles = data["openfhe"]["noise_budget_profiles"]
    assert set(profiles) == {"p0a_rotation", "day2_add_only", "day2_mult_only"}
    assert not data["openfhe"]["mixed_workload_parameterization"]["formal_parameter_claim_allowed"]
    assert data["blinding"]["mask_binding"] == MASK_BINDING
    assert data["blinding"]["mask_scope"] == "logical-coordinate-overlap-only"
    assert data["blinding"]["disjoint_output_rule"] == "concatenate-unmasked"
    assert data["blinding"]["output_plan_format"] == "dynamic-cssc-output-plan-v1"
    bounds = data["integer_correctness"]
    assert bounds["centered_result_abs_bound"] == 4096 * 7 * 1 == 28672
    assert bounds["twice_centered_result_abs_bound"] == 57344
    assert bounds["twice_centered_result_abs_bound"] < data["openfhe"]["plaintext_modulus"]
    assert data["synthetic_preflight"] == {
        "required_before_day1": True,
        "rows": 257,
        "cols": 521,
        "effective_slots": 256,
        "purpose": "exercise-multi-output-and-global-column-index-beyond-slot-range",
    }


def test_schema_accepts_manifest_and_closes_every_object() -> None:
    data = json.loads((ROOT / "config" / "params_manifest.json").read_text())
    schema = json.loads((ROOT / "config" / "params_manifest.schema.json").read_text())

    assert _schema_accepts(data, schema)
    _assert_all_objects_are_closed(schema)


def test_hidden_rowmap_requires_matrix_owner_masks() -> None:
    data = json.loads((ROOT / "config" / "params_manifest.json").read_text())
    broken = copy.deepcopy(data)
    broken["roles"]["mask_generator"] = "Cloud"
    with pytest.raises(ManifestError, match="matrix owner"):
        validate_manifest(broken)


def test_legacy_manifest_version_is_rejected() -> None:
    data = json.loads((ROOT / "config" / "params_manifest.json").read_text())
    broken = copy.deepcopy(data)
    broken["manifest_version"] = "0.1.1"
    with pytest.raises(ManifestError, match="manifest_version"):
        validate_manifest(broken)


def test_probe_labels_cannot_wrap_mod_t() -> None:
    data = json.loads((ROOT / "config" / "params_manifest.json").read_text())
    broken = copy.deepcopy(data)
    broken["openfhe"]["plaintext_modulus"] = broken["packing"]["total_slots"]
    with pytest.raises(ManifestError, match="exceed total_slots"):
        validate_manifest(broken)


@pytest.mark.parametrize(
    ("profile", "second_field"),
    [
        ("p0a_rotation", "eval_add_count"),
        ("day2_add_only", "key_switch_count"),
        ("day2_mult_only", "key_switch_count"),
    ],
)
def test_openfhe_noise_budget_profiles_are_mutually_exclusive(
    profile: str, second_field: str
) -> None:
    data = json.loads((ROOT / "config" / "params_manifest.json").read_text())
    broken = copy.deepcopy(data)
    broken["openfhe"]["noise_budget_profiles"][profile][second_field] = 1
    with pytest.raises(ManifestError, match="exactly one"):
        validate_manifest(broken)


def test_p0a_profile_must_be_key_switch_only() -> None:
    data = json.loads((ROOT / "config" / "params_manifest.json").read_text())
    broken = copy.deepcopy(data)
    broken["openfhe"]["noise_budget_profiles"]["p0a_rotation"]["operation_class"] = "add-only"
    with pytest.raises(ManifestError, match="p0a_rotation"):
        validate_manifest(broken)


def test_legacy_combined_noise_budget_fields_are_rejected() -> None:
    data = json.loads((ROOT / "config" / "params_manifest.json").read_text())
    broken = copy.deepcopy(data)
    broken["openfhe"]["multiplicative_depth"] = 2
    broken["openfhe"]["eval_add_count"] = 128
    broken["openfhe"]["key_switch_count"] = 16
    with pytest.raises(ManifestError, match="legacy combined"):
        validate_manifest(broken)


@pytest.mark.parametrize(
    ("path", "replacement", "message"),
    [
        (("matrix", "rows"), True, "integer"),
        (("matrix", "cols"), "8193", "integer"),
        (("packing", "effective_slots"), False, "integer"),
        (("runtime", "omp_threads"), "2", "integer"),
        (("freshness", "max_seconds"), "1.0", "number"),
        (("blinding", "mask_reuse_allowed"), 0, "boolean"),
        (("provenance", "held_out_required"), 1, "boolean"),
    ],
)
def test_numeric_and_boolean_fields_reject_coercion(
    path: tuple[str, ...], replacement: object, message: str
) -> None:
    data = json.loads((ROOT / "config" / "params_manifest.json").read_text())
    broken = copy.deepcopy(data)
    target = broken
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement

    with pytest.raises(ManifestError, match=message):
        validate_manifest(broken)


def test_unknown_fields_are_rejected_at_every_object_boundary() -> None:
    data = json.loads((ROOT / "config" / "params_manifest.json").read_text())
    schema = json.loads((ROOT / "config" / "params_manifest.schema.json").read_text())
    for path in [(), ("blinding",), ("openfhe", "noise_budget_profiles", "p0a_rotation")]:
        broken = copy.deepcopy(data)
        target = broken
        for key in path:
            target = target[key]
        target["unexpected"] = "must-fail"
        with pytest.raises(ManifestError, match="unexpected"):
            validate_manifest(broken)
        assert not _schema_accepts(broken, schema)


@pytest.mark.parametrize(
    ("path", "replacement", "message"),
    [
        (("threat_model", "cloud_non_collusion_with_clients"), False, "non-collusion"),
        (("leakage", "forbidden_to_cloud"), ["component-rowmaps"], "leakage"),
        (("randomness", "cryptographic", "source"), "mt19937", "CSPRNG"),
        (("randomness", "cryptographic", "modular_sampling"), "modulo-reduction", "rejection"),
        (("randomness", "experimental", "cryptographic_use_allowed"), True, "seed"),
        (("blinding", "mask_binding"), MASK_BINDING[:-3] + MASK_BINDING[-2:], "binding"),
        (("blinding", "binding_ledger", "owner"), "Cloud", "ledger"),
        (("blinding", "binding_ledger", "persistent"), False, "ledger"),
        (("blinding", "mask_scope"), "all-output-ciphertexts", "overlap"),
        (("blinding", "disjoint_output_rule"), "modular-sum", "disjoint"),
        (("blinding", "output_plan_format"), "dynamic-cssc-output-plan-v2", "format"),
        (("integer_correctness", "centered_result_abs_bound"), 28671, "bound"),
        (("integer_correctness", "twice_centered_result_abs_bound"), 57343, "twice"),
        (("matrix", "cols"), 4096, "effective slots"),
        (("matrix", "max_nnz_per_row"), 4097, "bound"),
        (("matrix", "max_nnz_per_row_scope"), "initial-state-only", "published"),
        (
            ("packing", "query_reorganization", "version_synchronized"),
            False,
            "version",
        ),
        (
            ("packing", "query_reorganization", "addressing"),
            "column-index-mod-effective-slots",
            "addressing",
        ),
        (
            ("packing", "query_reorganization", "communication_accounting_required"),
            False,
            "accounting",
        ),
        (("synthetic_preflight", "effective_slots"), 521, "preflight"),
    ],
)
def test_v21b_contract_mutations_fail_python_and_schema(
    path: tuple[str, ...], replacement: object, message: str
) -> None:
    data = json.loads((ROOT / "config" / "params_manifest.json").read_text())
    schema = json.loads((ROOT / "config" / "params_manifest.schema.json").read_text())
    broken = copy.deepcopy(data)
    target = broken
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement

    with pytest.raises(ManifestError, match=message):
        validate_manifest(broken)
    assert not _schema_accepts(broken, schema)


def test_column_index_leakage_and_versioned_query_reorganization_are_frozen() -> None:
    data = json.loads((ROOT / "config" / "params_manifest.json").read_text())
    assert "component-column-index-metadata" in data["leakage"]["allowed_to_client_b"]
    assert "component-column-index-metadata" in data["leakage"]["forbidden_to_cloud"]
    reorganization = data["packing"]["query_reorganization"]
    assert reorganization == {
        "mode": "versioned-column-index-per-cssc-chunk",
        "addressing": "global-column-index",
        "column_index_sender": "Client A",
        "column_index_recipient": "Client B",
        "column_index_visibility_to_cloud": False,
        "version_synchronized": True,
        "communication_accounting_required": True,
    }
    highest_column_index = data["matrix"]["cols"] - 1
    assert highest_column_index > data["packing"]["effective_slots"] - 1
    assert reorganization["addressing"] == "global-column-index"


@pytest.mark.parametrize("party_acl", ["allowed_to_client_a", "allowed_to_client_b"])
def test_full_output_plan_is_available_to_clients_but_forbidden_to_cloud(
    party_acl: str,
) -> None:
    data = json.loads((ROOT / "config" / "params_manifest.json").read_text())
    schema = json.loads((ROOT / "config" / "params_manifest.schema.json").read_text())
    resource = "component-rowmaps-and-output-plan"
    assert resource in data["leakage"][party_acl]
    assert resource in data["leakage"]["forbidden_to_cloud"]

    broken = copy.deepcopy(data)
    broken["leakage"][party_acl].remove(resource)
    with pytest.raises(ManifestError, match="leakage"):
        validate_manifest(broken)
    assert not _schema_accepts(broken, schema)


def test_output_plan_digest_is_public_but_full_plan_remains_hidden_from_cloud() -> None:
    data = json.loads((ROOT / "config" / "params_manifest.json").read_text())
    schema = json.loads((ROOT / "config" / "params_manifest.schema.json").read_text())
    leakage = data["leakage"]

    for party_acl in (
        "allowed_to_client_a",
        "allowed_to_client_b",
        "allowed_to_cloud",
    ):
        assert "output-plan-digest" in leakage[party_acl]

        broken = copy.deepcopy(data)
        broken["leakage"][party_acl].remove("output-plan-digest")
        with pytest.raises(ManifestError, match="leakage"):
            validate_manifest(broken)
        assert not _schema_accepts(broken, schema)

    assert "component-rowmaps-and-output-plan" not in leakage["allowed_to_cloud"]
    assert "component-rowmaps-and-output-plan" in leakage["forbidden_to_cloud"]


def test_frozen_at_schema_pattern_is_anchored() -> None:
    data = json.loads((ROOT / "config" / "params_manifest.json").read_text())
    schema = json.loads((ROOT / "config" / "params_manifest.schema.json").read_text())
    pattern = schema["properties"]["frozen_at"]["pattern"]
    assert pattern.startswith("^") and pattern.endswith("$")

    broken = copy.deepcopy(data)
    broken["frozen_at"] += "-trailing"
    with pytest.raises(ManifestError, match="frozen_at"):
        validate_manifest(broken)
    assert not _schema_accepts(broken, schema)


def test_integer_bound_is_tied_to_every_published_matrix_version() -> None:
    data = json.loads((ROOT / "config" / "params_manifest.json").read_text())
    assert data["matrix"]["max_nnz_per_row"] == data["integer_correctness"][
        "max_terms_per_output"
    ]
    assert data["matrix"]["max_nnz_per_row_scope"] == "all-published-versions"
