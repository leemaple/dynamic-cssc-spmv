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
    eval_add_count = int(_require(openfhe, "eval_add_count", "openfhe"))
    key_switch_count = int(_require(openfhe, "key_switch_count", "openfhe"))
    if total_slots != batch_size:
        raise ManifestError("packing.total_slots and openfhe.batch_size must agree")
    if batch_size > ring_dimension:
        raise ManifestError("BFV batch size must not exceed the frozen ring dimension")
    if plaintext_modulus <= total_slots:
        raise ManifestError("plaintext_modulus must exceed total_slots for the P0a labels")
    if (plaintext_modulus - 1) % (2 * ring_dimension) != 0:
        raise ManifestError("plaintext_modulus must be 1 mod 2N for the frozen CRT batching setup")
    if eval_add_count <= 0:
        raise ManifestError("openfhe.eval_add_count must be positive")
    if key_switch_count <= 0:
        raise ManifestError("openfhe.key_switch_count must be positive")

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
