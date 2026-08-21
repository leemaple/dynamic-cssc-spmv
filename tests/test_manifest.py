from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from dynamic_cssc.manifest import ManifestError, load_manifest, validate_manifest

ROOT = Path(__file__).resolve().parents[1]


def test_frozen_manifest_is_valid() -> None:
    data = load_manifest(ROOT / "config" / "params_manifest.json")
    assert data["manifest_version"] == "0.1.1"
    assert data["functional_mode"] == "F1-M-hidden-rowmap"
    assert data["openfhe"]["plaintext_modulus"] > data["packing"]["total_slots"]
    profiles = data["openfhe"]["noise_budget_profiles"]
    assert set(profiles) == {"p0a_rotation", "day2_add_only", "day2_mult_only"}
    assert not data["openfhe"]["mixed_workload_parameterization"]["formal_parameter_claim_allowed"]


def test_hidden_rowmap_requires_matrix_owner_masks() -> None:
    data = json.loads((ROOT / "config" / "params_manifest.json").read_text())
    broken = copy.deepcopy(data)
    broken["roles"]["mask_generator"] = "Cloud"
    with pytest.raises(ManifestError, match="matrix owner"):
        validate_manifest(broken)


def test_legacy_manifest_version_is_rejected() -> None:
    data = json.loads((ROOT / "config" / "params_manifest.json").read_text())
    broken = copy.deepcopy(data)
    broken["manifest_version"] = "0.1.0"
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
