from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


class ManifestError(ValueError):
    """Raised when the frozen P-1 manifest is internally inconsistent."""


def load_manifest(path: str | Path) -> dict[str, Any]:
    manifest_path = Path(path)
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ManifestError(f"manifest not found: {manifest_path}") from exc
    except json.JSONDecodeError as exc:
        raise ManifestError(f"invalid JSON in {manifest_path}: {exc}") from exc
    validate_manifest(data)
    return data


def _require(mapping: dict[str, Any], key: str, context: str) -> Any:
    if key not in mapping:
        raise ManifestError(f"missing {context}.{key}")
    return mapping[key]


def validate_manifest(data: dict[str, Any]) -> None:
    required_top = {
        "manifest_version",
        "functional_mode",
        "roles",
        "blinding",
        "matrix",
        "packing",
        "openfhe",
        "runtime",
        "freshness",
        "provenance",
    }
    missing = sorted(required_top - data.keys())
    if missing:
        raise ManifestError(f"missing top-level fields: {', '.join(missing)}")
    if data["manifest_version"] != "0.1.1":
        raise ManifestError("manifest_version must be 0.1.1 for the frozen noise-profile schema")

    matrix = data["matrix"]
    rows = int(_require(matrix, "rows", "matrix"))
    cols = int(_require(matrix, "cols", "matrix"))
    if rows <= 0 or cols <= 0:
        raise ManifestError("matrix dimensions must be positive")
    if matrix.get("dimension_mode") != "fixed":
        raise ManifestError("the first paper freezes matrix dimensions")

    packing = data["packing"]
    total_slots = int(_require(packing, "total_slots", "packing"))
    row_slots = int(_require(packing, "row_slots", "packing"))
    effective_slots = int(_require(packing, "effective_slots", "packing"))
    mode = _require(packing, "mode", "packing")
    if not (0 < effective_slots <= total_slots):
        raise ManifestError("packing.effective_slots must be in (0, total_slots]")
    if mode == "single-batching-row" and effective_slots > row_slots:
        raise ManifestError("single-row mode cannot use more than packing.row_slots")
    if row_slots * 2 != total_slots:
        raise ManifestError("v0.1 assumes two equal BFV batching rows")

    openfhe = data["openfhe"]
    if openfhe.get("scheme") != "BFVRNS":
        raise ManifestError("the first implementation must use BFVRNS")
    commit = str(_require(openfhe, "commit", "openfhe"))
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ManifestError("openfhe.commit must be a full 40-character lowercase SHA")
    ring_dimension = int(_require(openfhe, "ring_dimension", "openfhe"))
    plaintext_modulus = int(_require(openfhe, "plaintext_modulus", "openfhe"))
    batch_size = int(_require(openfhe, "batch_size", "openfhe"))
    if total_slots != batch_size:
        raise ManifestError("packing.total_slots and openfhe.batch_size must agree")
    if batch_size > ring_dimension:
        raise ManifestError("BFV batch size must not exceed the frozen ring dimension")
    if plaintext_modulus <= total_slots:
        raise ManifestError("plaintext_modulus must exceed total_slots for the P0a labels")
    if (plaintext_modulus - 1) % (2 * ring_dimension) != 0:
        raise ManifestError("plaintext_modulus must be 1 mod 2N for the frozen CRT batching setup")
    legacy_noise_fields = {"multiplicative_depth", "eval_add_count", "key_switch_count"}
    if legacy_noise_fields & openfhe.keys():
        raise ManifestError("legacy combined OpenFHE noise-budget fields are forbidden")
    profiles = _require(openfhe, "noise_budget_profiles", "openfhe")
    expected_profiles = {
        "p0a_rotation": ("key-switch-only", "p0a-layout-semantics-only"),
        "day2_add_only": ("add-only", "isolated-unit-probe-only"),
        "day2_mult_only": ("multiplication-only", "isolated-unit-probe-only"),
    }
    if set(profiles) != set(expected_profiles):
        raise ManifestError("openfhe.noise_budget_profiles must contain the frozen profiles")
    estimator_fields = ("multiplicative_depth", "eval_add_count", "key_switch_count")
    for profile_name, (operation_class, evidence_scope) in expected_profiles.items():
        profile = profiles[profile_name]
        counts = [
            int(_require(profile, field, f"openfhe.{profile_name}")) for field in estimator_fields
        ]
        if any(count < 0 for count in counts) or sum(count > 0 for count in counts) != 1:
            raise ManifestError(
                f"openfhe.{profile_name} must set exactly one noise estimator to a positive value"
            )
        if profile.get("operation_class") != operation_class:
            raise ManifestError(
                f"openfhe.{profile_name} must use operation_class={operation_class}"
            )
        if profile.get("evidence_scope") != evidence_scope:
            raise ManifestError(f"openfhe.{profile_name} must use evidence_scope={evidence_scope}")
    p0a_profile = profiles["p0a_rotation"]
    if int(p0a_profile["multiplicative_depth"]) != 0 or int(p0a_profile["eval_add_count"]) != 0:
        raise ManifestError("openfhe.p0a_rotation must be key-switch-only")
    add_profile = profiles["day2_add_only"]
    if int(add_profile["multiplicative_depth"]) != 0 or int(add_profile["key_switch_count"]) != 0:
        raise ManifestError("openfhe.day2_add_only must be add-only")
    mult_profile = profiles["day2_mult_only"]
    if int(mult_profile["eval_add_count"]) != 0 or int(mult_profile["key_switch_count"]) != 0:
        raise ManifestError("openfhe.day2_mult_only must be multiplication-only")

    mixed = _require(openfhe, "mixed_workload_parameterization", "openfhe")
    if mixed.get("status") != "unfrozen" or mixed.get("formal_parameter_claim_allowed", True):
        raise ManifestError("mixed-workload OpenFHE parameterization is not frozen")
    if mixed.get("required_gate") != "mixed-circuit-decryption-correctness":
        raise ManifestError(
            "mixed-workload parameterization requires a decryption correctness gate"
        )

    mode_name = data["functional_mode"]
    roles = data["roles"]
    blinding = data["blinding"]
    if mode_name == "F1-M-hidden-rowmap":
        if not blinding.get("enabled", False):
            raise ManifestError("F1-M requires blinding")
        if blinding.get("rowmap_visibility_to_cloud", True):
            raise ManifestError("hidden-rowmap mode cannot reveal RowMap to the cloud")
        if roles.get("mask_generator") != roles.get("matrix_owner"):
            raise ManifestError(
                "hidden-rowmap F1-M requires the RowMap-aware matrix owner to generate masks"
            )
        if blinding.get("mode") != "encrypted-one-time-zero-sum":
            raise ManifestError("hidden-rowmap F1-M requires encrypted one-time zero-sum masks")
        if blinding.get("mask_reuse_allowed", True):
            raise ManifestError("zero-sum masks must never be reused")

    freshness = data["freshness"]
    if float(_require(freshness, "max_seconds", "freshness")) <= 0:
        raise ManifestError("freshness.max_seconds must be positive")
    if int(_require(freshness, "microbatch_max_updates", "freshness")) <= 0:
        raise ManifestError("freshness.microbatch_max_updates must be positive")

    provenance = data["provenance"]
    if not provenance.get("predicted_and_measured_must_be_separate", False):
        raise ManifestError("predicted and measured data must be separated")
    if not provenance.get("held_out_required", False):
        raise ManifestError("held-out evaluation is mandatory")
