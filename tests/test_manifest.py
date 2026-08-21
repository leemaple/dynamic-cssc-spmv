from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from dynamic_cssc.manifest import ManifestError, load_manifest, validate_manifest

ROOT = Path(__file__).resolve().parents[1]


def test_frozen_manifest_is_valid() -> None:
    data = load_manifest(ROOT / "config" / "params_manifest.json")
    assert data["functional_mode"] == "F1-M-hidden-rowmap"
    assert data["openfhe"]["plaintext_modulus"] > data["packing"]["total_slots"]


def test_hidden_rowmap_requires_matrix_owner_masks() -> None:
    data = json.loads((ROOT / "config" / "params_manifest.json").read_text())
    broken = copy.deepcopy(data)
    broken["roles"]["mask_generator"] = "Cloud"
    with pytest.raises(ManifestError, match="matrix owner"):
        validate_manifest(broken)


def test_probe_labels_cannot_wrap_mod_t() -> None:
    data = json.loads((ROOT / "config" / "params_manifest.json").read_text())
    broken = copy.deepcopy(data)
    broken["openfhe"]["plaintext_modulus"] = broken["packing"]["total_slots"]
    with pytest.raises(ManifestError, match="exceed total_slots"):
        validate_manifest(broken)


@pytest.mark.parametrize("field", ["eval_add_count", "key_switch_count"])
def test_frozen_noise_budget_counts_must_be_positive(field: str) -> None:
    data = json.loads((ROOT / "config" / "params_manifest.json").read_text())
    broken = copy.deepcopy(data)
    broken["openfhe"][field] = 0
    with pytest.raises(ManifestError, match=field):
        validate_manifest(broken)
